<#
.SYNOPSIS
    Pester tests for Get-CapiDot1xDiagnosis (802.1X / NPS certificate diagnosis)

.DESCRIPTION
    All event log, service and certificate store access is mocked, so the tests run on any machine
    without CAPI2 data, NPS or administrator rights.

.EXAMPLE
    Invoke-Pester -Path .\Tests\Dot1xDiagnosis.Tests.ps1
#>

BeforeAll {
    $ModulePath = Join-Path $PSScriptRoot '..\CAPI2Tools.psm1'
    Import-Module $ModulePath -Force
}

Describe 'Get-CapiDot1xDiagnosis' {

    BeforeAll {
        Mock -ModuleName CAPI2Tools Get-CapiAllErrors {
            [PSCustomObject]@{
                TimeCreated = (Get-Date).AddSeconds(-20)
                TaskID      = '5C69DBE2-E66C-4F61-8FBD-EBE16F6610D8'
                Certificate = 'pc123.contoso.com'
                ErrorCount  = 1
                Errors      = 'CERT_E_UNTRUSTEDROOT'
                Events      = @()
            }
        }

        Mock -ModuleName CAPI2Tools Get-Service { [PSCustomObject]@{ Status = 'Running' } }

        Mock -ModuleName CAPI2Tools Get-ChildItem {
            [PSCustomObject]@{
                Subject             = 'CN=nps01.contoso.com'
                Issuer              = 'CN=Contoso Issuing CA'
                Thumbprint          = 'AABBCCDD'
                NotAfter            = (Get-Date).AddDays(-5)
                HasPrivateKey       = $true
                EnhancedKeyUsageList = @([PSCustomObject]@{ ObjectId = '1.3.6.1.5.5.7.3.1' })
            }
        }

        Mock -ModuleName CAPI2Tools Get-WinEvent { }

        Mock -ModuleName CAPI2Tools Get-WinEvent {
            [PSCustomObject]@{ IsEnabled = $true }
        } -ParameterFilter { $ListLog }

        Mock -ModuleName CAPI2Tools Get-WinEvent {
            $Event = [PSCustomObject]@{ TimeCreated = (Get-Date); Id = 6273 }
            $Event | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
                '<Event><EventData><Data Name="SubjectUserName">host/pc123.contoso.com</Data><Data Name="CallingStationID">AA-BB-CC-DD-EE-FF</Data><Data Name="ReasonCode">295</Data><Data Name="Reason">A certificate chain processed, but terminated in a root certificate which is not trusted</Data></EventData></Event>'
            }
            $Event
        } -ParameterFilter { $FilterHashtable -and $FilterHashtable.LogName -eq 'Security' -and $FilterHashtable.Id -contains 6273 }

        Mock -ModuleName CAPI2Tools Get-WinEvent {
            [PSCustomObject]@{
                TimeCreated  = (Get-Date)
                Id           = 12013
                LevelDisplayName = 'Error'
                Message      = "Wired 802.1X authentication failed.`r`nDetails"
            }
        } -ParameterFilter { $FilterHashtable -and $FilterHashtable.LogName -like '*Wired-AutoConfig*' }
    }

    It 'is exported by the module' {
        (Get-Module CAPI2Tools).ExportedFunctions.Keys | Should -Contain 'Get-CapiDot1xDiagnosis'
    }

    It 'rejects an invalid role' {
        { Get-CapiDot1xDiagnosis -Role 'Switch' } | Should -Throw
    }

    Context 'NPS role' {

        BeforeAll {
            $Result = Get-CapiDot1xDiagnosis -Role Nps -Hours 1 6>$null
        }

        It 'reports the rejection with parsed fields' {
            @($Result.NpsRejections).Count | Should -Be 1
            $Result.NpsRejections[0].ReasonCode | Should -Be 295
            $Result.NpsRejections[0].UserName | Should -Be 'host/pc123.contoso.com'
            $Result.NpsRejections[0].CertificateRelated | Should -BeTrue
        }

        It 'correlates the rejection with the CAPI2 error chain' {
            $Result.NpsRejections[0].CorrelatedErrors | Should -Be 'CERT_E_UNTRUSTEDROOT'
        }

        It 'uses the NPS side guidance for the CAPI2 error' {
            $Finding = $Result.Findings | Where-Object { $_.Source -eq 'CAPI2' }
            $Finding.Recommendation | Should -Match 'NTAuth'
        }

        It 'flags the expired Server Authentication certificate' {
            ($Result.Findings | Where-Object { $_.Source -eq 'Certificates' -and $_.Severity -eq 'Critical' }).Summary | Should -Match 'Expired'
        }

        It 'sorts critical findings first' {
            $Result.Findings[0].Severity | Should -Be 'Critical'
        }

        It 'filters by name' {
            $Filtered = Get-CapiDot1xDiagnosis -Role Nps -Name '*unknown-host*' -SkipCertificateInventory 6>$null
            @($Filtered.NpsRejections).Count | Should -Be 0
            @($Filtered.CapiChains).Count | Should -Be 0
        }
    }

    Context 'Client role' {

        BeforeAll {
            $Result = Get-CapiDot1xDiagnosis -Role Client -Hours 1 6>$null
        }

        It 'uses the client side guidance' {
            $Finding = $Result.Findings | Where-Object { $_.Source -eq 'CAPI2' }
            $Finding.Recommendation | Should -Match 'client'
        }

        It 'collects client authentication events' {
            @($Result.ClientEvents).Count | Should -BeGreaterThan 0
            $Result.ClientEvents[0].Message | Should -Be 'Wired 802.1X authentication failed.'
        }
    }

    Context 'Export' {

        BeforeAll {
            $TempDir = Join-Path $env:TEMP "Dot1xTests_$([guid]::NewGuid().ToString('N'))"
        }

        AfterAll {
            Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'writes an HTML report' {
            Get-CapiDot1xDiagnosis -Role Nps -ExportPath $TempDir 6>$null | Out-Null
            $File = Get-ChildItem -Path $TempDir -Filter '*.html'
            $File | Should -Not -BeNullOrEmpty
            (Get-Content -Path $File.FullName -Raw) | Should -Match 'CERT_E_UNTRUSTEDROOT'
        }

        It 'writes a JSON report' {
            Get-CapiDot1xDiagnosis -Role Nps -ExportPath $TempDir -Format JSON 6>$null | Out-Null
            $File = Get-ChildItem -Path $TempDir -Filter '*.json'
            { Get-Content -Path $File.FullName -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
    }
}

Describe 'Test-Dot1xCertificateReason' {

    It 'treats TLS stack reason codes as certificate related' {
        InModuleScope CAPI2Tools {
            Test-Dot1xCertificateReason -ReasonCode 295 -Reason '' | Should -BeTrue
        }
    }

    It 'matches English and German certificate texts' {
        InModuleScope CAPI2Tools {
            Test-Dot1xCertificateReason -ReasonCode 1 -Reason 'The certificate has expired' | Should -BeTrue
            Test-Dot1xCertificateReason -ReasonCode 1 -Reason 'Das Zertifikat ist abgelaufen' | Should -BeTrue
        }
    }

    It 'does not flag credential failures' {
        InModuleScope CAPI2Tools {
            Test-Dot1xCertificateReason -ReasonCode 16 -Reason 'Authentication failed due to a user credentials mismatch' | Should -BeFalse
        }
    }
}
