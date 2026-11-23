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

        Mock -ModuleName CAPI2Tools Get-Dot1xNpsAuditStatus {
            [PSCustomObject]@{ Success = $true; Failure = $true; Setting = 'Success and Failure' }
        }

        Mock -ModuleName CAPI2Tools Get-Dot1xCapi2Coverage {
            [PSCustomObject]@{ Oldest = (Get-Date).AddHours(-5); Newest = (Get-Date) }
        }

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

        It 'does not report the audit policy when success and failure are audited' {
            $Result.Findings | Where-Object { $_.Source -eq 'Audit policy' } | Should -BeNullOrEmpty
        }

        It 'warns when failures are not audited' {
            Mock -ModuleName CAPI2Tools Get-Dot1xNpsAuditStatus {
                [PSCustomObject]@{ Success = $true; Failure = $false; Setting = 'Success' }
            }
            $Audit = Get-CapiDot1xDiagnosis -Role Nps -SkipCertificateInventory 6>$null
            $Finding = $Audit.Findings | Where-Object { $_.Source -eq 'Audit policy' }
            $Finding.Severity | Should -Be 'Warning'
            $Finding.Recommendation | Should -Match '0CCE9243-69AE-11D9-BED3-505054503030'
        }

        It 'does not check the audit policy for the client role' {
            Get-CapiDot1xDiagnosis -Role Client -SkipCertificateInventory 6>$null | Out-Null
            Should -Invoke -ModuleName CAPI2Tools Get-Dot1xNpsAuditStatus -Times 0 -Scope It
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

    Context 'NPS summary and diagnostics' {

        It 'summarizes rejections per client' {
            $Result = Get-CapiDot1xDiagnosis -Role Nps -SkipCertificateInventory 6>$null
            @($Result.AffectedClients).Count | Should -Be 1
            $Result.AffectedClients[0].AccountName | Should -Be 'host/pc123.contoso.com'
            $Result.AffectedClients[0].Rejections | Should -Be 1
            $Result.AffectedClients[0].ReasonCodes | Should -Be '295'
        }

        It 'correlates a non-certificate rejection (internal error) with a CAPI2 error at the same time' {
            Mock -ModuleName CAPI2Tools Get-WinEvent {
                $Event = [PSCustomObject]@{ TimeCreated = (Get-Date); Id = 6274 }
                $Event | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
                    '<Event><EventData><Data Name="SubjectUserName">host/pc123.contoso.com</Data><Data Name="ReasonCode">1</Data><Data Name="Reason">An internal error occurred.</Data></EventData></Event>'
                }
                $Event
            } -ParameterFilter { $FilterHashtable -and $FilterHashtable.LogName -eq 'Security' -and $FilterHashtable.Id -contains 6273 }
            $Result = Get-CapiDot1xDiagnosis -Role Nps -SkipCertificateInventory 6>$null
            $Result.NpsRejections[0].CertificateRelated | Should -BeFalse
            $Result.NpsRejections[0].CorrelatedErrors | Should -Be 'CERT_E_UNTRUSTEDROOT'
            $Finding = $Result.Findings | Where-Object { $_.Summary -match 'Reason code 1:' }
            $Finding.Recommendation | Should -Match 'CERT_E_UNTRUSTEDROOT'
        }

        It 'returns a typed object with counts for the short default display' {
            $Result = Get-CapiDot1xDiagnosis -Role Nps -SkipCertificateInventory 6>$null
            $Result.PSObject.TypeNames[0] | Should -Be 'CAPI2Tools.Dot1xDiagnosis'
            $Result.RejectionCount | Should -Be 1
            $Result.ChainCount | Should -Be 1
            $Result.FindingCount | Should -Be @($Result.Findings).Count
        }

        It 'warns when the CAPI2 log started after the rejection' {
            Mock -ModuleName CAPI2Tools Get-CapiAllErrors { }
            Mock -ModuleName CAPI2Tools Get-Dot1xCapi2Coverage {
                [PSCustomObject]@{ Oldest = (Get-Date).AddMinutes(10); Newest = (Get-Date).AddMinutes(11) }
            }
            $Result = Get-CapiDot1xDiagnosis -Role Nps -SkipCertificateInventory 6>$null
            $Finding = $Result.Findings | Where-Object { $_.Source -eq 'CAPI2 log' }
            $Finding.Severity | Should -Be 'Warning'
            $Finding.Summary | Should -Match 'starts at'
        }

        It 'warns when the CAPI2 log is empty' {
            Mock -ModuleName CAPI2Tools Get-CapiAllErrors { }
            Mock -ModuleName CAPI2Tools Get-Dot1xCapi2Coverage { [PSCustomObject]@{ Oldest = $null; Newest = $null } }
            $Result = Get-CapiDot1xDiagnosis -Role Nps -SkipCertificateInventory 6>$null
            ($Result.Findings | Where-Object { $_.Source -eq 'CAPI2 log' }).Summary | Should -Match 'no events'
        }

        It 'points to Schannel and NTAuth when CAPI2 covered the time but has no error' {
            Mock -ModuleName CAPI2Tools Get-CapiAllErrors { }
            $Result = Get-CapiDot1xDiagnosis -Role Nps -SkipCertificateInventory 6>$null
            $Finding = $Result.Findings | Where-Object { $_.Source -eq 'CAPI2 log' }
            $Finding.Severity | Should -Be 'Info'
            $Finding.Recommendation | Should -Match 'Schannel'
        }

        It 'reports Schannel/NPS events from the System log' {
            Mock -ModuleName CAPI2Tools Get-WinEvent {
                [PSCustomObject]@{ TimeCreated = (Get-Date); ProviderName = 'Schannel'; Id = 36888; LevelDisplayName = 'Error'; Message = 'A fatal alert was generated.' }
            } -ParameterFilter { $FilterHashtable -and $FilterHashtable.LogName -eq 'System' }
            $Result = Get-CapiDot1xDiagnosis -Role Nps -SkipCertificateInventory 6>$null
            @($Result.SystemEvents).Count | Should -Be 1
            ($Result.Findings | Where-Object { $_.Source -eq 'System log' }).Summary | Should -Match 'Schannel'
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

Describe 'Convert-Dot1xRejection (real-world 6273, anonymized)' {

    BeforeAll {
        # Modeled on a real PEAP denial on a wired port: reason code 265, machine authentication
        $Xml = '<Event><EventData><Data Name="SubjectUserName">host/pc01.corp.contoso.com</Data><Data Name="FullyQualifiedSubjectUserName">CONTOSO\PC01$</Data><Data Name="CalledStationID">00-11-22-33-44-55</Data><Data Name="CallingStationID">AA-BB-CC-DD-EE-FF</Data><Data Name="NASIPv4Address">10.0.0.10</Data><Data Name="ClientName">SW-ACCESS-01</Data><Data Name="NetworkPolicyName">802.1X-Wired</Data><Data Name="AuthenticationType">PEAP</Data><Data Name="EAPType">-</Data><Data Name="ReasonCode">265</Data><Data Name="Reason">The certificate chain was issued by an authority that is not trusted.</Data></EventData></Event>'
        $Script:RealEvent = [PSCustomObject]@{ TimeCreated = (Get-Date); Id = 6273 }
        $Script:RealEvent | Add-Member -MemberType NoteProperty -Name Xml -Value $Xml
        $Script:RealEvent | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
    }

    It 'extracts account, switch and policy details' {
        $Row = InModuleScope CAPI2Tools -Parameters @{ Event = $Script:RealEvent } { param($Event) Convert-Dot1xRejection -Event $Event }
        $Row.UserName | Should -Be 'CONTOSO\PC01$'
        $Row.AccountName | Should -Be 'host/pc01.corp.contoso.com'
        $Row.NasIPv4Address | Should -Be '10.0.0.10'
        $Row.ClientName | Should -Be 'SW-ACCESS-01'
        $Row.AuthenticationType | Should -Be 'PEAP'
        $Row.ReasonCode | Should -Be 265
        $Row.CertificateRelated | Should -BeTrue
    }

    It 'has a concrete recommendation for reason code 265' {
        InModuleScope CAPI2Tools {
            $Script:Dot1xReasonGuidance[265] | Should -Match 'NTAuth'
        }
    }
}

Describe 'Get-CapiEventCertificateName' {

    It 'reads the subjectName attribute of events 41/42 (revocation errors)' {
        InModuleScope CAPI2Tools {
            $Xml = [xml]'<CertVerifyRevocation xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Certificate fileRef="AB.cer" subjectName="pc01.contoso.com" /><Result value="80092013" /></CertVerifyRevocation>'
            Get-CapiEventCertificateName -EventXml $Xml | Should -Be 'pc01.contoso.com'
        }
    }

    It 'reads a subjectName element' {
        InModuleScope CAPI2Tools {
            $Xml = [xml]'<Event><subjectName>www.contoso.com</subjectName></Event>'
            Get-CapiEventCertificateName -EventXml $Xml | Should -Be 'www.contoso.com'
        }
    }

    It 'returns nothing when there is no name' {
        InModuleScope CAPI2Tools {
            Get-CapiEventCertificateName -EventXml ([xml]'<Event><Result value="0" /></Event>') | Should -BeNullOrEmpty
        }
    }
}

Describe 'ConvertTo-Dot1xAuditStatus' {

    It 'parses English and German settings' {
        InModuleScope CAPI2Tools {
            $En = ConvertTo-Dot1xAuditStatus -Setting 'Success and Failure'
            $En.Success | Should -BeTrue
            $En.Failure | Should -BeTrue
            $De = ConvertTo-Dot1xAuditStatus -Setting 'Erfolg und Fehler'
            $De.Success | Should -BeTrue
            $De.Failure | Should -BeTrue
        }
    }

    It 'detects partial and disabled auditing' {
        InModuleScope CAPI2Tools {
            (ConvertTo-Dot1xAuditStatus -Setting 'Failure').Success | Should -BeFalse
            (ConvertTo-Dot1xAuditStatus -Setting 'Failure').Failure | Should -BeTrue
            $None = ConvertTo-Dot1xAuditStatus -Setting 'No Auditing'
            $None.Success | Should -BeFalse
            $None.Failure | Should -BeFalse
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
