<#
.SYNOPSIS
    DER split-report and engineer-handoff generation engine.

.DESCRIPTION
    Produces easy-to-consume HTML reports plus machine-readable JSON/CSV.
    Manual actions are enriched from the versioned Microsoft portal-path
    catalog so every known MAN-ID includes role, current click path, steps,
    verification guidance, and Microsoft Learn source links.

.NOTES
    Required parent entry point: New-DERFinalReports
#>


# Maintenance notes
# Responsibility: Builds engineer/operator reports from already-collected evidence; reporting must not become a hidden tenant-write path.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Test-DERReportingCommand {param([Parameter(Mandatory)][string]$Name)return[bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERReportingLog {param([string]$Level,[string]$Message,$Data)if(Test-DERReportingCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Reporting' -Message $Message -Data $Data}}
function ConvertTo-DERHtmlSafe {param($Value) return [System.Net.WebUtility]::HtmlEncode([string]$Value)}
function Read-DERReportJson {param([string]$Path)if(-not(Test-Path -LiteralPath $Path)){return $null};try{Get-Content -LiteralPath $Path -Raw -ErrorAction Stop|ConvertFrom-Json -Depth 100}catch{throw "DER report JSON is malformed/unreadable at '$Path': $($_.Exception.Message)"}}

function Get-DERPortalPathCatalog {
    [CmdletBinding()]
    param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot))
    $path=Join-Path $ProjectRoot 'Definitions\Portal\DER-PortalPathCatalog.json'
    $catalog=Read-DERReportJson -Path $path
    if(-not $catalog){throw "DER portal-path catalog is missing or invalid: $path"}
    if([string]$catalog.schemaVersion -ne '1.0'){throw "Unsupported DER portal-path catalog schema: $($catalog.schemaVersion)"}
    return $catalog
}


function Get-DERReportTemplateCatalog {
    [CmdletBinding()]
    param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot))
    $path=Join-Path $ProjectRoot 'Templates\Reports\DER-ReportTemplates.json'
    $templates=Read-DERReportJson -Path $path
    if(-not $templates){throw "DER report-template catalog is missing or invalid: $path"}
    if([string]$templates.schemaVersion -ne '1.0'){throw "Unsupported DER report-template schema: $($templates.schemaVersion)"}
    return $templates
}

function Read-DERWorkloadResults {
    param([string]$RunRoot)
    $root=Join-Path $RunRoot 'Workloads';if(-not(Test-Path -LiteralPath $root)){return @()}
    $r=@();foreach($f in Get-ChildItem -LiteralPath $root -Filter '*.json' -File -ErrorAction Stop){$j=Read-DERReportJson $f.FullName;if($j){$r+=$j}}
    return @($r)
}

function ConvertTo-DERMetadataMap {
    param($Metadata)
    $map=@{}
    if(-not $Metadata){return $map}
    if($Metadata -is [System.Collections.IDictionary]){foreach($k in $Metadata.Keys){$map[[string]$k]=$Metadata[$k]};return $map}
    foreach($p in $Metadata.PSObject.Properties){$map[[string]$p.Name]=$p.Value}
    return $map
}

function ConvertTo-DERDisplayValue {
    param($Value)
    if($null -eq $Value){return ''}
    if($Value -is [string]){return $Value}
    if($Value -is [System.Collections.IEnumerable]){return (@($Value)|ForEach-Object{[string]$_}) -join ', '}
    return [string]$Value
}

function Expand-DERManualTemplateText {
    param([string]$Text,$Metadata)
    if([string]::IsNullOrWhiteSpace($Text)){return $Text}
    $map=ConvertTo-DERMetadataMap -Metadata $Metadata
    return [regex]::Replace($Text,'\{\{([A-Za-z0-9_]+)\}\}',{
        param($m)
        $key=$m.Groups[1].Value
        if($map.ContainsKey($key)){return ConvertTo-DERDisplayValue $map[$key]}
        return ('<{0}: not supplied>' -f $key)
    })
}

function Get-DERPortalFallback {
    param([string]$Category)
    $entra=@('AuthenticationMethods','ConditionalAccess','Groups','NamedLocations','GuestExternal','AppConsent','PIM','PasswordProtection','EntraDevice','Identity','PIM','Guest Access','External Collaboration','Emergency Access')
    if($Category -in $entra){return [pscustomobject]@{Portal='Microsoft Entra admin center';PortalUrl='https://entra.microsoft.com';ClickPath=@('Use the object/module named in the DER finding');MinimumRole='Use least-privileged role appropriate to the object'}}
    return [pscustomobject]@{Portal='Microsoft Intune admin center';PortalUrl='https://intune.microsoft.com';ClickPath=@('Use the object/module named in the DER finding');MinimumRole='Use least-privileged role appropriate to the object'}
}

function ConvertTo-DEREnrichedManualAction {
    param([Parameter(Mandatory)]$Action,[Parameter(Mandatory)]$Catalog)
    $entry=@($Catalog.entries|Where-Object {$_.id -eq [string]$Action.Id}|Select-Object -First 1)
    $metadata=$Action.Metadata
    if($entry.Count -gt 0){
        $e=$entry[0]
        $steps=@($e.steps|ForEach-Object{Expand-DERManualTemplateText -Text ([string]$_) -Metadata $metadata})
        $verify=@($e.verification|ForEach-Object{Expand-DERManualTemplateText -Text ([string]$_) -Metadata $metadata})
        $path=@($e.clickPath|ForEach-Object{Expand-DERManualTemplateText -Text ([string]$_) -Metadata $metadata})
        $docs=@($e.docs)
        return [pscustomobject][ordered]@{
            Id=[string]$Action.Id;Status='Open';Owner='';Notes='';CompletedAt=$null;Priority=[string]$Action.Priority;Category=[string]$Action.Category;Title=[string]$Action.Title;Reason=[string]$Action.Reason;
            MinimumRole=[string]$e.minimumRole;Portal=[string]$e.portal;PortalUrl=[string]$e.portalUrl;ClickPath=$path;Steps=$steps;Verification=$verify;Documentation=$docs;CatalogMatch=$true
        }
    }
    $fallback=Get-DERPortalFallback -Category ([string]$Action.Category)
    return [pscustomobject][ordered]@{
        Id=[string]$Action.Id;Status='Open';Owner='';Notes='';CompletedAt=$null;Priority=[string]$Action.Priority;Category=[string]$Action.Category;Title=[string]$Action.Title;Reason=[string]$Action.Reason;
        MinimumRole=$fallback.MinimumRole;Portal=$fallback.Portal;PortalUrl=$fallback.PortalUrl;ClickPath=@($fallback.ClickPath);Steps=@('Review the DER finding and Action/Graph logs.','Make the minimum required correction in the appropriate Microsoft admin center.','Rerun DER and require read-back validation before closing this item.');Verification=@('DER rerun succeeds and read-back validation passes.');Documentation=@();CatalogMatch=$false
    }
}

function New-DERHtmlDocument {
    param([string]$Title,[string]$Subtitle,[string]$Body)
    $t=ConvertTo-DERHtmlSafe $Title;$s=ConvertTo-DERHtmlSafe $Subtitle
    return @"
<!doctype html><html><head><meta charset="utf-8"><title>$t</title><style>
:root{font-family:Segoe UI,Arial,sans-serif;color:#1f2328;background:#fff}body{margin:32px;line-height:1.48}h1{margin:0 0 4px}h2{margin-top:28px;border-bottom:1px solid #d8dee4;padding-bottom:6px}h3{margin:0 0 8px}.sub{color:#656d76;margin-bottom:24px}.ok{color:#137333}.warn{color:#9a6700}.bad{color:#b42318}.muted{color:#656d76}table{border-collapse:collapse;width:100%;margin:12px 0 24px}th,td{border:1px solid #d8dee4;padding:8px;vertical-align:top;text-align:left}th{background:#f6f8fa}code{background:#f6f8fa;padding:2px 4px;border-radius:3px}.pill{display:inline-block;padding:3px 9px;border:1px solid #afb8c1;border-radius:12px;margin:0 6px 6px 0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px}.card{border:1px solid #d8dee4;border-radius:8px;padding:16px;break-inside:avoid}.critical{border-left:5px solid #b42318}.high{border-left:5px solid #d97706}.normal{border-left:5px solid #0969da}.low{border-left:5px solid #57606a}.path{background:#f6f8fa;border-radius:6px;padding:9px;margin:8px 0}.small{font-size:.9em;color:#656d76}ol,ul{margin-top:6px;padding-left:24px}a{color:#0969da;text-decoration:none}a:hover{text-decoration:underline}.callout{border:1px solid #d8dee4;background:#f6f8fa;border-radius:8px;padding:12px 14px;margin:14px 0}.pagebreak{page-break-before:always}
@media print{body{margin:12mm}.card{break-inside:avoid}.no-print{display:none}a{color:#000;text-decoration:none}}
</style></head><body><h1>$t</h1><div class="sub">$s</div>$Body</body></html>
"@
}

function ConvertTo-DERHtmlTable {
    param([object[]]$Rows,[string[]]$Columns)
    if(-not $Rows -or $Rows.Count -eq 0){return '<p class="muted">None.</p>'}
    $h='<table><thead><tr>';foreach($c in $Columns){$h+='<th>'+ (ConvertTo-DERHtmlSafe $c) +'</th>'};$h+='</tr></thead><tbody>'
    foreach($row in $Rows){$h+='<tr>';foreach($c in $Columns){$v=$null;if($row -is [System.Collections.IDictionary]){$v=$row[$c]}elseif($row.PSObject.Properties.Name -contains $c){$v=$row.$c};if($v -is [System.Collections.IEnumerable] -and -not($v -is [string])){$v=(@($v)|ForEach-Object{ConvertTo-DERDisplayValue $_}) -join '; '};$h+='<td>'+ (ConvertTo-DERHtmlSafe $v) +'</td>'};$h+='</tr>'};$h+='</tbody></table>';return $h
}

function ConvertTo-DERHtmlOrderedList {
    param([object[]]$Items)
    if(-not $Items -or $Items.Count -eq 0){return '<p class="muted">None.</p>'}
    $h='<ol>';foreach($i in $Items){$h+='<li>'+ (ConvertTo-DERHtmlSafe $i) +'</li>'};$h+='</ol>';return $h
}

function ConvertTo-DERHtmlUnorderedList {
    param([object[]]$Items)
    if(-not $Items -or $Items.Count -eq 0){return '<p class="muted">None.</p>'}
    $h='<ul>';foreach($i in $Items){$h+='<li>'+ (ConvertTo-DERHtmlSafe $i) +'</li>'};$h+='</ul>';return $h
}

function ConvertTo-DERManualActionsHtml {
    param([object[]]$Actions,[string]$CatalogVersion,[string]$VerifiedDate)
    if(-not $Actions -or $Actions.Count -eq 0){return '<p class="ok"><strong>No manual actions are currently required.</strong></p>'}
    $h="<div class='callout'><strong>Portal path catalog:</strong> $(ConvertTo-DERHtmlSafe $CatalogVersion) &nbsp; <strong>Microsoft Learn paths verified:</strong> $(ConvertTo-DERHtmlSafe $VerifiedDate)<br><span class='small'>Portal labels can move. The MAN-ID, reason, and verification requirement remain authoritative even if Microsoft later renames a blade.</span></div><div class='cards'>"
    foreach($a in $Actions){
        $cls=([string]$a.Priority).ToLowerInvariant();if($cls -notin @('critical','high','normal','low')){$cls='normal'}
        $path=(@($a.ClickPath)|ForEach-Object{ConvertTo-DERHtmlSafe $_}) -join ' &gt; '
        $portalLink='<a href="'+(ConvertTo-DERHtmlSafe $a.PortalUrl)+'">'+(ConvertTo-DERHtmlSafe $a.Portal)+'</a>'
        $h+="<section class='card $cls'><h3>$(ConvertTo-DERHtmlSafe $a.Id) — $(ConvertTo-DERHtmlSafe $a.Title)</h3>"
        $h+="<p><span class='pill'>$(ConvertTo-DERHtmlSafe $a.Priority)</span><span class='pill'>$(ConvertTo-DERHtmlSafe $a.Category)</span><span class='pill'>Status: Open</span></p><p class='small'><strong>Owner:</strong> ____________________ &nbsp;&nbsp; <strong>Completed:</strong> ____________________</p>"
        $h+="<p><strong>Why:</strong> $(ConvertTo-DERHtmlSafe $a.Reason)</p><p><strong>Minimum role:</strong> $(ConvertTo-DERHtmlSafe $a.MinimumRole)<br><strong>Portal:</strong> $portalLink</p><div class='path'><strong>Click path:</strong><br>$path</div>"
        $h+='<strong>Do this:</strong>'+(ConvertTo-DERHtmlOrderedList -Items @($a.Steps))+'<strong>Close it only after:</strong>'+(ConvertTo-DERHtmlUnorderedList -Items @($a.Verification))
        if(@($a.Documentation).Count -gt 0){$h+='<strong>Microsoft Learn:</strong><ul>';foreach($d in @($a.Documentation)){$h+='<li><a href="'+(ConvertTo-DERHtmlSafe $d.url)+'">'+(ConvertTo-DERHtmlSafe $d.title)+'</a></li>'};$h+='</ul>'}
        if(-not $a.CatalogMatch){$h+='<p class="warn"><strong>Generic fallback:</strong> no exact MAN-ID catalog entry was available for this generated failure item.</p>'}
        $h+='</section>'
    }
    $h+='</div>';return $h
}

function Write-DERHtmlReport {param([string]$Path,[string]$Title,[string]$Subtitle,[string]$Body) $html=New-DERHtmlDocument -Title $Title -Subtitle $Subtitle -Body $Body;[System.IO.File]::WriteAllText($Path,$html,[System.Text.UTF8Encoding]::new($false));return $Path}

function New-DERFinalReports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)]$Discovery,
        [Parameter(Mandatory)]$Analysis,
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)]$DryRun,
        $Validation,
        $PermissionPlan,
        $Adoption,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )
    $ctx=if(Test-DERReportingCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null}
    $tenantId=$BuildPlan.TenantId;$tenantName=$BuildPlan.TenantName
    $root=Join-Path (Join-Path (Join-Path $RuntimeRoot 'Reports') $tenantId) $RunId;New-Item -ItemType Directory -Path $root -Force|Out-Null
    $runRoot=if($ctx){$ctx.RunRoot}else{Join-Path (Join-Path (Join-Path $RuntimeRoot 'Runs') $tenantId) $RunId}
    $workloadResults=@(Read-DERWorkloadResults -RunRoot $runRoot)
    $validationResults=if($Validation){@($Validation.Results)}else{@()}
    $state=if(Test-DERReportingCommand 'Get-DERCurrentState'){Get-DERCurrentState}else{$null}
    $catalog=Get-DERPortalPathCatalog
    $templates=Get-DERReportTemplateCatalog
    $loggingSummary=if(Test-DERReportingCommand 'Get-DERLoggingSummary'){Get-DERLoggingSummary}else{$null}

    $accomplished=@($validationResults|Where-Object {$_.Status -eq 'Passed'}|Select-Object Module,DerId,DisplayName,ObjectId,Reason)
    $failed=@($validationResults|Where-Object {$_.Status -eq 'Failed'}|Select-Object Module,DerId,DisplayName,ObjectId,Reason)
    foreach($wr in $workloadResults){foreach($x in @($wr.Results|Where-Object {$_.Status -eq 'Failed'})){if(-not(@($failed|Where-Object {$_.DerId -eq $x.DerId}).Count)){$failed+= [pscustomobject]@{Module=$wr.Module;DerId=$x.DerId;DisplayName=$x.DisplayName;ObjectId=$x.ObjectId;Reason=$x.Message}}}}
    $skipped=@($validationResults|Where-Object {$_.Status -eq 'Skipped'}|Select-Object Module,DerId,DisplayName,ObjectId,Reason)
    foreach($wr in $workloadResults){foreach($x in @($wr.Results|Where-Object {$_.Status -eq 'Skipped'})){if(-not(@($skipped|Where-Object {$_.DerId -eq $x.DerId}).Count)){$skipped+= [pscustomobject]@{Module=$wr.Module;DerId=$x.DerId;DisplayName=$x.DisplayName;ObjectId=$x.ObjectId;Reason=$x.Message}}}}

    $manual=New-Object System.Collections.Generic.List[object]
    foreach($m in @($BuildPlan.ManualActions)){$manual.Add((ConvertTo-DEREnrichedManualAction -Action $m -Catalog $catalog))}
    foreach($f in $failed){
        $failAction=[pscustomobject]@{Id=('FAIL-{0}' -f $f.DerId);Priority='High';Category=[string]$f.Module;Title=("Resolve failed DER action {0}" -f $f.DerId);Reason=[string]$f.Reason;Metadata=$null}
        $manual.Add((ConvertTo-DEREnrichedManualAction -Action $failAction -Catalog $catalog))
    }
    $manual=@($manual|Sort-Object @{Expression={switch($_.Priority){'Critical'{0};'High'{1};'Normal'{2};'Low'{3};default{4}}}},Category,Id)

    $applicable=[math]::Max(1,[int]$BuildPlan.Summary.PlannedObjects);$passed=@($accomplished).Count;$completion=[math]::Round(($passed/$applicable)*100,1)
    $subtitle="$tenantName | Tenant $tenantId | Run $RunId"
    $adoptedCount=if($Adoption -and $Adoption.Summary){[int]$Adoption.Summary.Adopted}else{0}
    $adoptionCandidateCount=if($Adoption -and $Adoption.Summary){[int]$Adoption.Summary.Candidates}else{0}
    $summaryBody="<p><span class='pill'>Baseline completion: $completion%</span><span class='pill'>Accomplished: $($accomplished.Count)</span><span class='pill'>Failed: $($failed.Count)</span><span class='pill'>Skipped: $($skipped.Count)</span><span class='pill'>Manual: $($manual.Count)</span><span class='pill'>Adopted: $adoptedCount</span></p>"
    $summaryBody+="<h2>Safety</h2><p>Existing customer objects modified: <strong>$($BuildPlan.Summary.CustomerOwnedObjectsModified)</strong><br>Existing customer objects deleted: <strong>$($BuildPlan.Summary.CustomerOwnedObjectsDeleted)</strong><br>Production enforcement enabled by DER: <strong>$($BuildPlan.Summary.ProductionEnforcement)</strong><br>Ownership-only customer objects adopted: <strong>$adoptedCount</strong> (no tenant write or assignment change during adoption)</p>"
    if($manual.Count -gt 0){$summaryBody+="<h2>Manual work remaining</h2><p><strong>$($manual.Count)</strong> open item(s). Start with Critical/High items in <code>04 - Manual Actions.html</code>.</p>"}
    $summaryBody+='<h2>Top Existing Tenant Findings</h2>'+ (ConvertTo-DERHtmlTable -Rows @($Analysis.Findings|Select-Object -First 20 Severity,Category,Title,Recommendation) -Columns @('Severity','Category','Title','Recommendation'))
    Write-DERHtmlReport -Path (Join-Path $root '00 - Executive Summary.html') -Title 'DER Executive Summary' -Subtitle $subtitle -Body $summaryBody|Out-Null
    Write-DERHtmlReport -Path (Join-Path $root '01 - Accomplished.html') -Title 'Accomplished' -Subtitle $subtitle -Body (ConvertTo-DERHtmlTable -Rows $accomplished -Columns @('Module','DerId','DisplayName','ObjectId','Reason'))|Out-Null
    Write-DERHtmlReport -Path (Join-Path $root '02 - Failed.html') -Title 'Failed' -Subtitle $subtitle -Body (ConvertTo-DERHtmlTable -Rows $failed -Columns @('Module','DerId','DisplayName','ObjectId','Reason'))|Out-Null
    Write-DERHtmlReport -Path (Join-Path $root '03 - Skipped.html') -Title 'Skipped' -Subtitle $subtitle -Body (ConvertTo-DERHtmlTable -Rows $skipped -Columns @('Module','DerId','DisplayName','ObjectId','Reason'))|Out-Null

    $manualBody=ConvertTo-DERManualActionsHtml -Actions $manual -CatalogVersion ([string]$catalog.catalogVersion) -VerifiedDate ([string]$catalog.verifiedDate)
    Write-DERHtmlReport -Path (Join-Path $root '04 - Manual Actions.html') -Title 'Manual Actions' -Subtitle $subtitle -Body $manualBody|Out-Null
    ConvertTo-Json -InputObject @($manual) -Depth 40|Set-Content -LiteralPath (Join-Path $root '04 - Manual Actions.json') -Encoding UTF8
    $manualCsv=@($manual|ForEach-Object{[pscustomobject][ordered]@{Id=$_.Id;Status=$_.Status;Owner=$_.Owner;CompletedAt=$_.CompletedAt;Notes=$_.Notes;Priority=$_.Priority;Category=$_.Category;Title=$_.Title;Reason=$_.Reason;MinimumRole=$_.MinimumRole;Portal=$_.Portal;PortalUrl=$_.PortalUrl;ClickPath=(@($_.ClickPath)-join ' > ');Steps=(@($_.Steps)-join ' | ');Verification=(@($_.Verification)-join ' | ');Documentation=(@($_.Documentation)|ForEach-Object{$_.url}) -join ' | '}})
    $manualCsvPath=Join-Path $root '04 - Manual Actions.csv'
    if($manualCsv.Count -gt 0){$manualCsv|Export-Csv -LiteralPath $manualCsvPath -NoTypeInformation -Encoding UTF8}else{[System.IO.File]::WriteAllText($manualCsvPath,'"Id","Status","Owner","CompletedAt","Notes","Priority","Category","Title","Reason","MinimumRole","Portal","PortalUrl","ClickPath","Steps","Verification","Documentation"'+[Environment]::NewLine,[System.Text.UTF8Encoding]::new($false))}

    Write-DERHtmlReport -Path (Join-Path $root '05 - Existing Tenant Findings.html') -Title 'Existing Tenant Findings' -Subtitle $subtitle -Body (ConvertTo-DERHtmlTable -Rows @($Analysis.Findings) -Columns @('Severity','Category','FindingType','Title','Detail','Recommendation'))|Out-Null
    $beforeAfter="<h2>Before</h2><p>PRE-BUILD snapshot: <code>$(ConvertTo-DERHtmlSafe $Analysis.SnapshotRoot)</code></p><h2>After</h2><p>Validated DER objects: $passed<br>Failed validation: $($failed.Count)<br>Skipped: $($skipped.Count)</p>"
    Write-DERHtmlReport -Path (Join-Path $root '06 - Before and After.html') -Title 'Before and After' -Subtitle $subtitle -Body $beforeAfter|Out-Null
    $ownership=if($state){@($state.Objects|Select-Object OwnershipClass,Status,DerId,ObjectType,DisplayName,ObjectId,CreatedByRunId,BaselineVersion)}else{@()}
    Write-DERHtmlReport -Path (Join-Path $root '07 - DER Ownership Manifest.html') -Title 'DER Ownership Manifest' -Subtitle $subtitle -Body (ConvertTo-DERHtmlTable -Rows $ownership -Columns @('OwnershipClass','Status','DerId','ObjectType','DisplayName','ObjectId','CreatedByRunId','BaselineVersion'))|Out-Null
    $permRows=if($PermissionPlan){@($PermissionPlan.RequiredScopes|ForEach-Object{[pscustomobject]@{Scope=$_;Purpose='Approved build write scope'}})}else{@()}
    Write-DERHtmlReport -Path (Join-Path $root '08 - Permissions and Tenant Changes.html') -Title 'Permissions and Tenant Changes' -Subtitle $subtitle -Body ((ConvertTo-DERHtmlTable -Rows $permRows -Columns @('Scope','Purpose'))+"<h2>Tenant-wide planned actions</h2>"+(ConvertTo-DERHtmlTable -Rows @($BuildPlan.Objects|Where-Object {$_.SafeState -match 'approval|tenant'}|Select-Object DerId,Module,DisplayName,SafeState) -Columns @('DerId','Module','DisplayName','SafeState')))|Out-Null
    $activation=@();$activationStep=0
    foreach($actionText in @($templates.productionActivationChecklist)){$activationStep++;$activation += [pscustomobject]@{Step=$activationStep;Action=[string]$actionText}}
    Write-DERHtmlReport -Path (Join-Path $root '09 - Production Activation Checklist.html') -Title 'Production Activation Checklist' -Subtitle $subtitle -Body (ConvertTo-DERHtmlTable -Rows $activation -Columns @('Step','Action'))|Out-Null
    $drift=@($validationResults|Where-Object {$_.Differences -and @($_.Differences).Count -gt 0}|ForEach-Object{[pscustomobject]@{Module=$_.Module;DerId=$_.DerId;DisplayName=$_.DisplayName;Differences=(@($_.Differences)|ConvertTo-Json -Depth 10 -Compress)}})
    Write-DERHtmlReport -Path (Join-Path $root '10 - Configuration Drift.html') -Title 'Configuration Drift' -Subtitle $subtitle -Body (ConvertTo-DERHtmlTable -Rows $drift -Columns @('Module','DerId','DisplayName','Differences'))|Out-Null

    $handoff="<h2>Run status</h2><p><span class='pill'>Completion $completion%</span><span class='pill'>$($failed.Count) failed</span><span class='pill'>$($manual.Count) manual</span><span class='pill'>$($drift.Count) drift</span></p>"
    if($failed.Count -gt 0){$handoff+='<h2>Failures requiring attention</h2>'+(ConvertTo-DERHtmlTable -Rows $failed -Columns @('Module','DerId','DisplayName','Reason'))}
    $handoff+='<h2>Manual action queue</h2>'+(ConvertTo-DERHtmlTable -Rows @($manual|Select-Object Id,Priority,Category,Title,Portal,@{N='ClickPath';E={@($_.ClickPath)-join ' > '}}) -Columns @('Id','Priority','Category','Title','Portal','ClickPath'))
    $handoff+='<h2>Configuration drift</h2>'+(ConvertTo-DERHtmlTable -Rows $drift -Columns @('Module','DerId','DisplayName','Differences'))
    if($Adoption){$handoff+='<h2>Customer-object adoption</h2>'+(ConvertTo-DERHtmlTable -Rows @($Adoption.Candidates|Select-Object DerId,Module,DisplayName,ObjectId,ComparisonScope,Decision,Notes) -Columns @('DerId','Module','DisplayName','ObjectId','ComparisonScope','Decision','Notes'))}
    if($loggingSummary){
        $handoff+=("<h2>Run diagnostics</h2><p><span class='pill'>{0} engine errors</span><span class='pill'>{1} action errors</span><span class='pill'>{2} warnings</span><span class='pill'>{3} unique incidents</span></p><p class='small'>Engine errors mean DER/PowerShell/runtime failed. Action errors mean DER executed the requested action path but Microsoft, tenant state, validation, or the requested operation could not complete. Action IDs correlate work; Incident IDs correlate repeated observations of the same underlying exception. Neither identifier changes failure provenance.</p>" -f [long]$loggingSummary.EngineErrorCount,[long]$loggingSummary.ActionErrorCount,[long]$loggingSummary.WarningCount,[long]$loggingSummary.UniqueIncidentCount)
        $handoff+=(ConvertTo-DERHtmlTable -Rows @([pscustomobject]@{Log='Engine errors';Path=$loggingSummary.EngineErrorLog},[pscustomobject]@{Log='Action errors';Path=$loggingSummary.ActionErrorLog},[pscustomobject]@{Log='Combined structured errors';Path=$loggingSummary.StructuredErrorLog},[pscustomobject]@{Log='Action timeline';Path=$loggingSummary.ActionLog},[pscustomobject]@{Log='Engine timeline';Path=$loggingSummary.EngineLog},[pscustomobject]@{Log='Graph forensic';Path=$loggingSummary.GraphLog},[pscustomobject]@{Log='Validation';Path=$loggingSummary.ValidationLog},[pscustomobject]@{Log='Rollback';Path=$loggingSummary.RollbackLog},[pscustomobject]@{Log='Technical';Path=$loggingSummary.TechnicalLog},[pscustomobject]@{Log='Transcript';Path=$loggingSummary.TranscriptLog}) -Columns @('Log','Path'))
    }
    $handoff+=("<h2>Handoff rule</h2><p>{0}</p>" -f (ConvertTo-DERHtmlSafe $templates.engineerHandoff.closeRule))
    Write-DERHtmlReport -Path (Join-Path $root '11 - Engineer Handoff.html') -Title 'Engineer Handoff' -Subtitle $subtitle -Body $handoff|Out-Null

    $adoptionRows=if($Adoption){@($Adoption.Candidates|Select-Object DerId,Module,ObjectType,DisplayName,ObjectId,ComparisonScope,ComparisonComplete,DifferenceCount,CandidateStatus,Decision,DecisionSource,Notes)}else{@()}
    $adoptionBody="<p><strong>Safety rule:</strong> Adoption changes DER local ownership state only. DER does not modify the tenant object or its assignments during adoption.</p><p>Candidates: <strong>$adoptionCandidateCount</strong> | Adopted: <strong>$adoptedCount</strong></p>"+(ConvertTo-DERHtmlTable -Rows $adoptionRows -Columns @('DerId','Module','ObjectType','DisplayName','ObjectId','ComparisonScope','ComparisonComplete','DifferenceCount','CandidateStatus','Decision','DecisionSource','Notes'))
    Write-DERHtmlReport -Path (Join-Path $root '12 - Adoption Decisions.html') -Title 'Customer Object Adoption Decisions' -Subtitle $subtitle -Body $adoptionBody|Out-Null

    $machine=[pscustomobject][ordered]@{SchemaVersion='1.2';RunId=$RunId;TenantId=$tenantId;TenantName=$tenantName;CompletionPercent=$completion;Accomplished=$accomplished;Failed=$failed;Skipped=$skipped;ManualActions=$manual;ExistingFindings=$Analysis.Findings;Ownership=$ownership;Drift=$drift;Adoption=$Adoption;Logging=$loggingSummary;PortalPathCatalog=[pscustomobject]@{Version=$catalog.catalogVersion;VerifiedDate=$catalog.verifiedDate};ReportTemplates=[pscustomobject]@{Version=$templates.templateVersion};GeneratedAt=(Get-Date).ToString('o')}
    $machine|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $root 'DER-ReportData.json') -Encoding UTF8
    $reportIndex=[pscustomobject][ordered]@{SchemaVersion='1.1';RunId=$RunId;GeneratedAt=(Get-Date).ToString('o');Primary='00 - Executive Summary.html';EngineerHandoff='11 - Engineer Handoff.html';Adoption='12 - Adoption Decisions.html';ManualActions=[pscustomobject]@{Html='04 - Manual Actions.html';Json='04 - Manual Actions.json';Csv='04 - Manual Actions.csv'};Files=@('00 - Executive Summary.html','01 - Accomplished.html','02 - Failed.html','03 - Skipped.html','04 - Manual Actions.html','04 - Manual Actions.json','04 - Manual Actions.csv','05 - Existing Tenant Findings.html','06 - Before and After.html','07 - DER Ownership Manifest.html','08 - Permissions and Tenant Changes.html','09 - Production Activation Checklist.html','10 - Configuration Drift.html','11 - Engineer Handoff.html','12 - Adoption Decisions.html','DER-ReportData.json')}
    $reportIndex|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root 'DER-ReportIndex.json') -Encoding UTF8
    Write-DERReportingLog -Level OK -Message ("DER report set generated at {0}." -f $root) -Data @{completion=$completion;accomplished=$accomplished.Count;failed=$failed.Count;skipped=$skipped.Count;manual=$manual.Count;portalCatalog=$catalog.catalogVersion}
    return [pscustomobject]@{ReportRoot=$root;CompletionPercent=$completion;Accomplished=$accomplished.Count;Failed=$failed.Count;Skipped=$skipped.Count;ManualActions=$manual.Count;Adopted=$adoptedCount;AdoptionCandidates=$adoptionCandidateCount;PortalCatalogVersion=$catalog.catalogVersion;ReportTemplateVersion=$templates.templateVersion}
}

Export-ModuleMember -Function @('ConvertTo-DERHtmlSafe','Get-DERPortalPathCatalog','Get-DERReportTemplateCatalog','Expand-DERManualTemplateText','ConvertTo-DEREnrichedManualAction','New-DERHtmlDocument','ConvertTo-DERHtmlTable','ConvertTo-DERManualActionsHtml','New-DERFinalReports')
