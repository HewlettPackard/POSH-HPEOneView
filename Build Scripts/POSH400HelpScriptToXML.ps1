[CmdLetBinding (DefaultParameterSetName = "Default")]
Param 
(
    
	[Parameter (Position = 0, Mandatory = $False, HelpMessage = "Provide the root directory to where the Library source is located.")]
    [ValidateNotNullorEmpty()]
	[string]$LibrarySource = "$(Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)\.."

)

$LibraryGuid = '9f892d35-7eda-4de9-aaab-172d6076b2e9'
$MamlHelpFileName = "HPOneView.400.psm1-help.xml"

$Script:ExcludeParamNames = 'WhatIf','Confirm'

function Convert-EmbeddedToXml 
{

	[CmdLetBinding (DefaultParameterSetName = "Default")]
    Param 
    (
        
		[parameter (Mandatory = $false, ParameterSetName = "Default", Position = 1)]
		[String]$TrunkLocation = $LibrarySource

	)
	 
	Begin
	{

		$Script:GHPagesRepo = 'C:\Users\chris\Documents\GIT\GitHub\gh-pages'

		$WriteLog = $False

		if ($Global:BuildLogfile)
		{

			$WriteLog = $True

			Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Begin writing PowerShell MAML XML Help file."

		}

		if ($null -eq $Global:Version)
		{

			[System.Version]$Version = $null

			$PSMVersion = ((GC "$LibrarySource\HPOneView.400.psm1") -match '^\[version\]\$script:ModuleVersion = ') -replace '\[version\]\$script:ModuleVersion = ','' -replace '"',''

			[void][System.Version]::TryParse($PSMVersion, [ref]$Version)

		}

		Write-Verbose ('PSM Version: {0}' -f $Version)

		$Library = "$LibrarySource\HPOneView.400.psd1"

		if (-not(Test-Path "$TrunkLocation\Build Scripts\HPOneView.400_CmdletHelp.json"))
		{

			Log-Error -LogPath $Global:BuildLogfile -ErrorDesc ("The Cmdlet Help Contents JSON file is missing from {0}\Build Scripts\HPOneView.400_CmdletHelp.json.  Please validate this file exists." -f $TrunkLocation)
			
			Write-Error ("The Cmdlet Help Contents JSON file is missing from {0}\Build Scripts\HPOneView.400_CmdletHelp.json.  Please validate this file exists." -f $TrunkLocation) -ErrorAction Stop
		
		}

		Try
		{

			[System.Collections.ArrayList]$CmdletHelpContents = GC ('{0}\Build Scripts\HPOneView.400_CmdletHelp.json' -f $TrunkLocation) | Out-String | ConvertFrom-Json
			$_CmdletHelpContentsCount = $CmdletHelpContents.Count

		}

		Catch
		{

			$PSCmdlet.ThrowTerminatingError($_)

		}		

		$MamlLocation = $env:TEMP + '\MamlOneViewHelpFiles'

		$FixDocumentation = [PSCustomObject]@{ MissingHelpParams = New-Object System.Collections.ArrayList; UndocumentedCmdlets = New-Object System.Collections.ArrayList}

	}
	
	Process
	{

		$Global:MissingHelpParameterDef = New-Object System.Collections.ArrayList
		$Global:UndocumentedCmdlets     = New-Object System.Collections.ArrayList
		$MamlHelpFileLocation = Join-Path "$MamlLocation" "FinalXML"

		if (-not (Test-Path "$MamlLocation")) 
		{ 
		
			New-Item -Path "$MamlLocation" -type Directory 

			New-Item -Path (Join-Path "$MamlLocation" "FinalXML") -Type Directory

			New-Item -Path (Join-Path $MamlHelpFileLocation $MamlHelpFileName) -ItemType File
	
		}			

		if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Final help file location: '$MamlHelpFileLocation\$MamlHelpFileName'." }

		if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Creating XMLWriter object." }

		$result = $false

		$fileinfo = [System.IO.FileInfo] (gi "$MamlHelpFileLocation\$MamlHelpFileName").fullname

		try 
		{

			$stream = $fileInfo.Open([System.IO.FileMode]"Open",[System.IO.FileAccess]"ReadWrite",[System.IO.FileShare]"None")

			$stream.Dispose()

		} 
		
		catch [System.IO.IOException] 
		{

			if ($null -ne $Xml)
			{

				$XmlWriter.Dispose()
				$Xml = $null

			}

			else
			{

				Write-Error ('The {0} file is in use.  Either another process is creating the offline help file, or an error ocurred and there is an orphaned Write lock handle to the file.' -f $MamlHelpFileName) -ErrorAction Stop

			}

		}

		if (Test-Path "$TrunkLocation\en-US\$MamlHelpFileName" -PathType Leaf)
		{

			Remove-Item "$TrunkLocation\en-US\$MamlHelpFileName" -Force -Confirm:$false

		}		

		$XmlWriter         = New-Object System.XMl.XmlTextWriter("$MamlHelpFileLocation\$MamlHelpFileName",[Text.Encoding]::UTF8)
		$XmlWriterSettings = New-Object System.Xml.XmlWriterSettings
		
		# choose a pretty formatting:
		$XmlWriter.Formatting           = 'Indented'
		$XmlWriter.Indentation          = 1
		$XmlWriter.IndentChar           = "`t"
		$XmlWriterSettings.NewLineChars = "`n`r"
		 
		# write the header
		$XmlWriter.WriteProcessingInstruction("xml", "version='1.0'")
		
		# set XSL statements
		$xmlWriter.WriteStartElement('helpItems')
		$XmlWriter.WriteAttributeString('xmlns', 'http://msh')
		$XmlWriter.WriteAttributeString('schema', 'maml')

		if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Created XMLWriter object." }
    
		#Check to see if the library is loaded.  Remove if so.
		if (get-module HPOneView.400) 
		{ 
		
			Remove-Module HPOneView.400
	
		}

		Import-Module $library

		#Get all commands from the library
		[array]$commands = Get-Command -Module HPOneView.400 | ? { $_.CommandType -in 'Function','Filter' } 
		#[array]$commands = "Add-HPOVBaseline" #,"New-HPOVProfile"

		$c = 1

		Try
		{

			if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Generating PowerShell Library MAML XML Help file" }
   
			#FOREACH loop to process CMDLETs and their help documentation
			foreach ($command in ($commands | ? Name -ne "prompt" )) 
			{

				$_CmdletBase = Get-Help -full HPOneView.400\$command
				
                $_CmdletHelpContent = ($CmdletHelpContents | ? Name -EQ $command.Name).Contents
				
                $XmlWriter.WriteComment($_CmdletBase.Name.ToUpper()) 
				
                if (-not $_CmdletHelpContent)
                {
					
                    $UndocumentedCmdlet = [PSCustomObject]@{Name = $command}

                    [void]$UndocumentedCmdlets.Add($UndocumentedCmdlet)
                    [Void]$FixDocumentation.UndocumentedCmdlets.Add($UndocumentedCmdlet)

                    Write-Warning ("'{0}' is not documented.  Creating skeleton help." -f $UndocumentedCmdlet.Name)
					
					$_NewSkeletonCmdlet = New-HelpSkeleton $command $commands $_CmdletBase
					
					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Adding {0} skeleton Cmdlet Help to collection." }

					[void]$CmdletHelpContents.Add($_NewSkeletonCmdlet)

                }
				
				# else
				# {
				
					Write-Progress -Id 300 -Activity "Generating PowerShell Library MAML XML Help file" -Status ('"Processing ({0}/{1})' -f $c,$commands.count ) -CurrentOperation $command.Name -PercentComplete ($c/$($commands.count) * 70)

					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Processing $command ($c/$($commands.count))" }

					#region XML Header
					#Write Command Details node
					$xmlWriter.WriteStartElement('command:command')
					$XmlWriter.WriteAttributeString('xmlns:maml', "http://schemas.microsoft.com/maml/2004/10")
					$XmlWriter.WriteAttributeString('xmlns:command', "http://schemas.microsoft.com/maml/dev/command/2004/10")
					$XmlWriter.WriteAttributeString('xmlns:dev', "http://schemas.microsoft.com/maml/dev/2004/10")
					$XmlWriter.WriteComment($_CmdletBase.Name.ToUpper())  
					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue ("[BUILDHELP] Processing {0} - Building CMDLET Synopsis" -f $command.Name) }

					$xmlWriter.WriteStartElement('command:details')
					$xmlWriter.WriteElementString('command:name',$command.Name)
		
					#CMDLET Synopsis
					$xmlWriter.WriteStartElement('maml:description')
					$xmlWriter.WriteElementString('maml:para',$_CmdletHelpContent.Synopsis)

					if ($_CmdletHelpContent.Synopsis -eq 'default content')
					{

						Write-Error ("'{0}' Cmdlet does not contain a Synopsis." -f $command.Name) -ErrorAction Continue

						[void]$MissingHelpParameterDef.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = 'Synopsis'})
						[Void]$FixDocumentation.MissingHelpParams.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = 'Synopsis'})

					}
		
					#Close maml:description
					$xmlWriter.WriteEndElement()
		
					#Write Verb
					$xmlWriter.WriteElementString('command:verb',$command.Name.Substring(0,$command.Name.IndexOf("-")))
		
					#Write Noun
					$xmlWriter.WriteElementString('command:noun',$command.Name.Substring($command.Name.IndexOf("-")+1))
		
					#$xmlWriter.WriteElementString('dev:version',$null)
		
					#Close command:details
					$xmlWriter.WriteEndElement()

					#CMDLET Full Description
					$xmlWriter.WriteStartElement('maml:description')
					$xmlWriter.WriteElementString('maml:para',$_CmdletHelpContent.Description)

					if ($_CmdletHelpContent.Description -eq 'default content')
					{

						Write-Error ("'{0}' Cmdlet does not contain a Description." -f $command.Name) -ErrorAction Continue

						[void]$MissingHelpParameterDef.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = 'Description'})
						[Void]$FixDocumentation.MissingHelpParams.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = 'Description'})

					}
			
					#Close maml:description
					$xmlWriter.WriteEndElement()
					#endregion

					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Processing $command - Building CMDLET Syntax" }

					#CMDLET Syntax options
					$xmlWriter.WriteStartElement('command:syntax')
					$XmlWriter.WriteComment('Parameter Sets') 

					foreach ($set in $_CmdletBase.syntax.syntaxItem) 
					{

						#Open Syntax entry
						$xmlWriter.WriteStartElement('command:syntaxItem')
						$xmlWriter.WriteElementString('maml:name',$set.name)

						foreach ($parameter in $set.parameter) 
						{

							$_ParameterDef = $_CmdletHelpContent.Parameters | ? Name -EQ $parameter.name

							#Open command:parameter
							$xmlWriter.WriteStartElement('command:parameter')
							$XmlWriter.WriteAttributeString('required',$_ParameterDef.ParameterValue.required)
							#$XmlWriter.WriteAttributeString('variableLength','false')
							$XmlWriter.WriteAttributeString('globbing',[bool]$parameter.globbing)
							$XmlWriter.WriteAttributeString('pipelineInput',$parameter.pipelineInput)
							$XmlWriter.WriteAttributeString('position',$parameter.position.ToString().ToLower())
							#$XmlWriter.WriteAttributeString('isDynamic',$parameter.isDynamic)
							$XmlWriter.WriteAttributeString('parameterSetName',$parameter.parameterSetName)
							#$XmlWriter.WriteAttributeString('aliases',$parameter.aliases)

							$xmlWriter.WriteElementString('maml:name',$parameter.name)

							#Open maml:description
							$xmlWriter.WriteStartElement('maml:description')

							if ((-not($_ParameterDef.Description) -or $_ParameterDef.Description -eq 'default content') -and ($ExcludeParamNames -notcontains $parameter.name) -and -not($MissingHelpParameterDef | ? { $_.Cmdlet -eq $command.Name -and $_.Parameter -eq  $parameter.name}))
							{

								Write-Error ("'{0}' in '{1}' Cmdlet does not contain a parameter Syntax description." -f $parameter.name, $command.Name) -ErrorAction Continue

								[void]$MissingHelpParameterDef.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = $parameter.name})
								[Void]$FixDocumentation.MissingHelpParams.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = $parameter.name})

								$xmlWriter.WriteElementString('maml:para',$null)

							}

							elseif (-not($_ParameterDef.Description) -and ($ExcludeParamNames -contains $parameter.name))
							{

								$xmlWriter.WriteElementString('maml:para',$null)

							}

							else
							{

								$xmlWriter.WriteElementString('maml:para',$_ParameterDef.Description) #.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;"))

							}								

							#Close maml:description
							$xmlWriter.WriteEndElement()

							#Open command:parameterValue
							$xmlWriter.WriteStartElement('command:parameterValue')
							$XmlWriter.WriteAttributeString('required',$_ParameterDef.ParameterValue.required)
							$XmlWriter.WriteAttributeString('variableLength',$false)
							$XmlWriter.WriteString($_ParameterDef.ParameterValue.value)

							#Close command:parameterValue
							$xmlWriter.WriteEndElement()

							#Close command:parameter
							$xmlWriter.WriteEndElement()

						}

						#Close Command syntaxItem
						$xmlWriter.WriteEndElement()

					}

					#Close command:syntax
					$xmlWriter.WriteEndElement()

					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Processing $command - Building CMDLET Parameters" }

					#Open command:parameters
					$xmlWriter.WriteStartElement('command:parameters')
					$XmlWriter.WriteComment('All Parameters')  
					foreach ($_ParameterDef in $_CmdletBase.parameters.parameter) 
					{

						foreach ($_param in $_ParameterDef) 
						{

							$_Parameter = $_CmdletHelpContent.Parameters | ? Name -EQ $_param.name

							#Command Parameter
							$xmlWriter.WriteStartElement('command:parameter')
							$XmlWriter.WriteAttributeString('required',$_Parameter.ParameterValue.required)
							#$XmlWriter.WriteAttributeString('variableLength',$false)
							$XmlWriter.WriteAttributeString('globbing',[bool]$_param.globbing)
							$XmlWriter.WriteAttributeString('pipelineInput',$_param.pipelineInput)
							$XmlWriter.WriteAttributeString('position',$_param.position.ToString().ToLower())
							#$XmlWriter.WriteAttributeString('isDynamic',$_param.isDynamic)
							$XmlWriter.WriteAttributeString('parameterSetName',$_param.parameterSetName)
							$XmlWriter.WriteAttributeString('aliases',$_param.aliases)

							$xmlWriter.WriteElementString('maml:name',$_param.name)

							#Parameter Description
							$xmlWriter.WriteStartElement('maml:description')

							#NEED TO REMOVE .CONTENTS property as already focused on the CONTENTS root
							if ((-not($_Parameter.Description) -or $_Parameter.Description -eq 'default content') -and ($ExcludeParamNames -notcontains $_param.name) -and -not(($MissingHelpParameterDef | ? { $_.Cmdlet -eq $command.Name }) | ? Parameter -eq $_param.name))
							{

								if (-not($_Parameter.Description) -and ($ExcludeParamNames -notcontains $_param.name))
								{

									Write-Error ("'{0}' in '{1}' Cmdlet does not contain a parameter set description." -f $_param.name, $command.Name) -ErrorAction Continue

									#[void]$MissingHelpParameterDef.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = $_param.name})
									#$FixDocumentation.MissingHelpParams.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = $parameter.name})

								}							

								$xmlWriter.WriteElementString('maml:para',$null)

							}
							
							elseif (-not($_Parameter.Description) -and ($ExcludeParamNames -contains $_param.name))
							{

								$xmlWriter.WriteElementString('maml:para',$null)

							}

							else
							{

								$xmlWriter.WriteElementString('maml:para',$_Parameter.Description) #.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;"))

							}

							#Close maml:description
							$xmlWriter.WriteEndElement()

							$xmlWriter.WriteStartElement('command:parameterValue')
							$XmlWriter.WriteAttributeString('required',$_Parameter.ParameterValue.required)
							$XmlWriter.WriteAttributeString('variableLength',$false)
							$XmlWriter.WriteString($_Parameter.ParameterValue.value)                 

							#Close Command Parameter
							$xmlWriter.WriteEndElement()
						
							#Parameter Type
							$xmlWriter.WriteStartElement('dev:type')
							$xmlWriter.WriteElementString('maml:name',$_Parameter.ParameterValue.value)
							#$xmlWriter.WriteElementString('maml:uri',$null)

							#Close Parameter Type
							$xmlWriter.WriteEndElement()

							#Parameter Default Value
							$xmlWriter.WriteElementString('dev:defaultValue',$_Parameter.DefaultValue)

							#Close PARAMETER Options
							$xmlWriter.WriteEndElement()

						}

					}

					#Close command:parameters
					$xmlWriter.WriteEndElement()

					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Processing $command - Building CMDLET Input Types" }

					#Open command:inputTypes
					$xmlWriter.WriteStartElement('command:inputTypes')
					$XmlWriter.WriteComment('Input Types')  
					foreach ($_input in $_CmdletHelpContent.InputTypes) 
					{          

						#Open command:inputType
						$xmlWriter.WriteStartElement('command:inputType')

						#Open dev:type
						$xmlWriter.WriteStartElement('dev:type')
					
						$xmlWriter.WriteElementString('maml:name',$_input.Value)
						#$xmlWriter.WriteElementString('maml:uri',$null)

						#Close dev:type
						$xmlWriter.WriteEndElement()
						
						#Open maml:description
						$xmlWriter.WriteStartElement('maml:description')
						$xmlWriter.WriteElementString('maml:para',$_input.Text)
						
						#Close maml:description
						$xmlWriter.WriteEndElement()
					
						#Close command:inputType
						$xmlWriter.WriteEndElement()

					}

					#Close command:inputTYpes
					$xmlWriter.WriteEndElement()

					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Processing $command - Building CMDLET Return Values" }

					#Open command:returnValue
					$xmlWriter.WriteStartElement('command:returnValues')
					$XmlWriter.WriteComment('Return Values')  
					foreach ($_return in $_CmdletHelpContent.ReturnValues) 
					{

						#Open command:returnValue
						$xmlWriter.WriteStartElement('command:returnValue')

						#Open dev:type
						$xmlWriter.WriteStartElement('dev:type')
					
						$xmlWriter.WriteElementString('maml:name',$_return.Value)
						$xmlWriter.WriteElementString('maml:uri',$null)

						#Close dev:type
						$xmlWriter.WriteEndElement()
						
						#Open maml:description
						$xmlWriter.WriteStartElement('maml:description')
						$xmlWriter.WriteElementString('maml:para',$_return.Text)
						
						#Close maml:description
						$xmlWriter.WriteEndElement()
					
						#Close command:returnValue
						$xmlWriter.WriteEndElement()

					}

					#Close command:returnValue
					$xmlWriter.WriteEndElement()

					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Processing $command - Building CMDLET Examples" }

					#Open command:examples
					$_e = 1
					$xmlWriter.WriteStartElement('command:examples')
					$XmlWriter.WriteComment('Examples')  
					ForEach ($_example in $_CmdletHelpContent.Examples)
					{

						#Open command:example
						$xmlWriter.WriteStartElement('command:example')

						$xmlWriter.WriteElementString('maml:title',$_example.Title)

						#Open maml:introduction
						$xmlWriter.WriteStartElement('maml:introduction')
						$xmlWriter.WriteElementString('maml:para',$null)

						#Close maml:introduction
						$xmlWriter.WriteEndElement()

						$xmlWriter.WriteElementString('dev:code',$_example.Code)

						#Open dev:remarks
						$xmlWriter.WriteStartElement('dev:remarks')
						$xmlWriter.WriteElementString('dev:para',$_example.Description)
						$xmlWriter.WriteElementString('dev:para',$null)

						#Close dev:remarks
						$xmlWriter.WriteEndElement()

						#Open command:commandLines
						$xmlWriter.WriteStartElement('command:commandLines')

						#Open command:commandLine
						$xmlWriter.WriteStartElement('command:commandLine')

						$xmlWriter.WriteElementString('command:commandText',$null)

						#Close command:commandLine
						$xmlWriter.WriteEndElement()

						#Close command:commandLines
						$xmlWriter.WriteEndElement()

						#Close command:example
						$xmlWriter.WriteEndElement()

						if ($_example.code.Contains('default content'))
						{

							Write-Error ("'{0}' Cmdlet example {1} does not contain a valid description." -f $command.Name, $_e) -ErrorAction Continue

							[void]$MissingHelpParameterDef.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = "Example $_e Description"})
							[Void]$FixDocumentation.MissingHelpParams.Add([PSCustomObject]@{Cmdlet = $command.Name; Parameter = "Example $_e Description"})

						}

						$_e++

					}

					#Close command:examples
					$xmlWriter.WriteEndElement()

					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Processing $command - Building CMDLET Related Links" }

					#Open maml:relatedLinks
					$xmlWriter.WriteStartElement('maml:relatedLinks')
					$XmlWriter.WriteComment('Related Links')  
					ForEach ($_link in $_CmdletHelpContent.RelatedLinks)
					{

						#Open maml:navigationLink
						$xmlWriter.WriteStartElement('maml:navigationLink')
						$xmlWriter.WriteElementString('maml:linkText',$_link.Text)
						$xmlWriter.WriteElementString('maml:uri',$_link.Uri)

						#Close maml:navigationLink
						$xmlWriter.WriteEndElement()

					}

					#Close maml:relatedLinks
					$xmlWriter.WriteEndElement()

					#Close command:command
					$xmlWriter.WriteEndElement()

					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Processing $command - Completed" }

				# }
	
				$c++
    
			}
			#END FOREACH Loop

			# finalize the document:
			$XmlWriter.WriteComment(('Edited on: {0}' -f ((get-date).ToUniversalTime()).ToString("yyyy-MM-ddTHH:mm:ss:ff.fffZ")))
			$xmlWriter.Flush()
			$xmlWriter.Close()

			Write-Progress -Id 300 -Activity "Generating PowerShell Library MAML XML Help file" -Completed

			if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Generating PowerShell Library MAML XML Help file - Completed" }

		}

		Catch
		{

			#Close the open file handle XmlWriter has
			$xmlWriter.Flush()
			$xmlWriter.Close()

			Write-Progress -Id 300 -Activity "Building final help '$MamlHelpFileName'" -Completed
    
			if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP - ERROR] $($_.Message)" }

			if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP - ERROR] $($_.ScriptStackTrace)" }

 			$PSCmdlet.ThrowTerminatingError($_)

		}

		remove-module HPOneView.400

		if ($MissingHelpParameterDef)
		{

			if ($WriteLog) { Log-Error -LogPath $Global:BuildLogfile -ErrorDesc ($MissingHelpParameterDef | Out-String)}

			Write-Host 'Missing Parameter Definitions:'
			Write-Host ($MissingHelpParameterDef | Out-String)

		}

		if ($UndocumentedCmdlets)
		{

			if ($WriteLog) { Log-Error -LogPath $Global:BuildLogFile -ErrorDesc ('Undocumented Cmdlets: {0}' -f ($UndocumentedCmdlets -join ', '))}
			
			Write-Host 'Undocumented Cmdlets:'
			Write-Host ($UndocumentedCmdlets | Out-String)

		}

		$FixDocumentation

		if ($CmdletHelpContents.Count -gt $_CmdletHelpContentsCount)
		{

			if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Contents of original Cmdlet help were updated. Updating JSON file." }

			ForEach ($_HelpEntry in $MissingHelpParameterDef)
			{

				Switch ($_HelpEntry.Parameter)
				{

					'ApplianceConnection'
					{

						$_CmdletParameter = New-ApplianceConnectionCmdletParameter

					}

					'Async'
					{

						$_CmdletParameter = New-AsyncCmdletParameter

					}

					'Credential'
					{

						$_CmdletParameter = New-PSCredentialCmdletParameter

					}

					'Scope'
					{

						$_CmdletParameter = New-ScopeCmdletParameter

					}

					default
					{

						$_CmdletParameter      = New-CmdletParameter
						$_CmdletParameter.Name = $_HelpEntry.Parameter

					}

				}

				if (-not(($CmdletHelpContents | ? Name -eq $_HelpEntry.Cmdlet).Contents.Parameters | ? Name -eq $_HelpEntry.Parameter) -and
				'Synopsis', 'Description' -notcontains $_HelpEntry.Parameter)
				{

					Write-Host ('Adding {0} parameter to {1} Cmdlet JSON' -f $_HelpEntry.Parameter, $_HelpEntry.Cmdlet) -ForegroundColor Cyan

					($CmdletHelpContents | ? Name -eq $_HelpEntry.Cmdlet).Contents.Parameters += $_CmdletParameter

				}

			}

			$CmdletHelpContents | ConvertTo-Json -Depth 99 | Out-File ('{0}\Build Scripts\HPOneView.400_CmdletHelp.json' -f $TrunkLocation) -Encoding utf8 -Force

		}

		Write-Progress -Id 300 -Activity "Building final help '$MamlHelpFileName'" -status "Copying 'HPOneView.400.psm1-help.xml' to $MamlHelpFileLocation\$MamlHelpFileName" -PercentComplete 75

		if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Copying 'HPOneView.400.psm1-help.xml' to $MamlHelpFileLocation\$MamlHelpFileName" }

		Copy-Item "$MamlHelpFileLocation\$MamlHelpFileName" "$TrunkLocation\en-US" -Force -Confirm:$False

		#Update library _HelpInfo.xml file
		[Array]$files = $Null
		$processFiles = New-Object System.Collections.ArrayList
		[Array]$files = (get-item $trunklocation\*_helpInfo.xml).FullName

		$CultureVersion = $Null

		$CultureVersionArray = @()

		Write-Progress -Id 300 -Activity "Building final help '$MamlHelpFileName'" -status "Updating UICulture Version" -PercentComplete 80

		ForEach ($_file in $files)
		{

			if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue ("[BUILDHELP] Updating '{0}' UICulture Version string" -f $_file) }

			$xmlFile = New-Object XML

			#Read XML file
			$xmlFile.Load($_file)

			#Check to see if there are multiple UICultures
			if ($xmlFile.HelpInfo.SupportedUICultures.UICulture -is [System.Array]) 
			{

				for ($i = 0; $i -lt $xmlFile.HelpInfo.SupportedUICultures.UICulture.Count; $i++) 
				{
                
					[System.Version]$UiCultureVersion = $null

					$tmpUiCultureVersion = $xmlFile.HelpInfo.SupportedUICultures.UICulture[$i].UICultureVersion

					[void][System.Version]::TryParse($tmpUiCultureVersion, [ref]$UiCultureVersion)

					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue ("[BUILDHELP] Original UICulture Version: {0}" -f $UiCultureVersion.ToString() )}

					if ($UiCultureVersion -lt $Version)
					{

						$CultureVersion = $Version.ToString()

					}
    
					elseif ($UiCultureVersion -ge $Version)
					{

						$CultureVersionArray = $UiCultureVersion -split "\."

						[int]$major    = $CultureVersionArray[0]
						[int]$minor    = $CultureVersionArray[1]
						[int]$build    = $CultureVersionArray[2]
						[int]$revision = $CultureVersionArray[3]
                
						$revision++

						[String]$CultureVersion = "$major.$minor.$build.$revision"

					}

					$xmlFile.HelpInfo.SupportedUICultures.UICulture[$i].UICultureVersion = $CultureVersion
					
					if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue ("[BUILDHELP] New UICulture Version: {0}" -f $CultureVersion) }

				}

			}

			#Only a single UICulture
			else
			{

				[System.Version]$UiCultureVersion = $null

				$tmpUiCultureVersion = $xmlFile.HelpInfo.SupportedUICultures.UICulture.UICultureVersion

				[void][System.Version]::TryParse($tmpUiCultureVersion, [ref]$UiCultureVersion)

				if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue ("[BUILDHELP] Original UICulture Version: {0}" -f $UiCultureVersion.ToString() )}
    
				if ($UiCultureVersion -lt $Version)
				{

					$CultureVersion = $Version.ToString()

				}
    
				else
				{

					$CultureVersionArray = $UiCultureVersion -split "\."

					[int]$major    = $CultureVersionArray[0]
					[int]$minor    = $CultureVersionArray[1]
					[int]$build    = $CultureVersionArray[2]
					[int]$revision = $CultureVersionArray[3]
                
					$revision++

					[String]$CultureVersion = "$major.$minor.$build.$revision"

				}

				$xmlFile.HelpInfo.SupportedUICultures.UICulture.UICultureVersion = $CultureVersion

				if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue ("[BUILDHELP] New UICulture Version: {0}" -f $CultureVersion) }
        
			}

			$xmlFile.Save($_file)

			$xmlFile = $null

		}

		[void]$processFiles.Add("$MamlHelpFileLocation\HPOneView.400.psm1-help.xml")

		Write-Progress -Id 300 -Activity "Building final help '$MamlHelpFileName'" -status "Creating CAB file for online update" -PercentComplete 90

		if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Creating CAB file for online update" }

        New-CabinetFile ("HPOneView.400_{0}_en-US_HelpContent.cab" -f $LibraryGuid) $processFiles $MamlHelpFileLocation #-Verbose
    
		if ($WriteLog) { Log-Write -LogPath $Global:BuildLogfile -LineValue ("[BUILDHELP] Copying Offline Help update files to GHPages Repo: {0}" -f ($GHPagesRepo + '\UpdateHelp'))}

        Copy-Item ("$LibrarySource\Build Scripts\MamlOneViewHelpFiles\FinalXML\HPOneView.400_{0}_en-US_HelpContent.cab" -f $LibraryGuid), ("$LibrarySource\HPOneView.400_{0}_HelpInfo.xml" -f $LibraryGuid) -Destination ($GHPagesRepo + '\UpdateHelp') -Force -Confirm:$false

		Write-Progress -Id 300 -Activity "Building final help '$MamlHelpFileName'" -PercentComplete 100
		Write-Progress -Id 300 -Activity "Building final help '$MamlHelpFileName'" -Completed

	}
    
    End
	{

		if($WriteLog)
		{
			
			Log-Write -LogPath $Global:BuildLogfile -LineValue "[BUILDHELP] Finsihed."

		}

	}

}

function New-HelpSkeleton ($_Command, $_Commands, $_CommandHelpFull)
{

	$_CmdletVerb = $_Command.Name.Split('-')[0]

	$_NewCmdletSkeleton = [PSCustomObject] @{

        Name     = $_Command.Name;
        Contents = [PSCustomObject]@{
        
            Synopsis     = 'Default content';
            Description  = 'Default content';
            Parameters   = New-Object System.Collections.ArrayList;
			InputTypes   = New-Object System.Collections.ArrayList;
            ReturnValues = New-Object System.Collections.ArrayList;
            Examples     = New-Object System.Collections.ArrayList;
			RelatedLinks = New-Object System.Collections.ArrayList
		
		}
        
	}

	ForEach ($_ParameterDef in $_CommandHelpFull.parameters.parameter)
	{

		foreach ($_param in $_ParameterDef) 
		{

			Write-Host ("-- Adding {0} parameter" -f $_param.Name) -ForegroundColor Cyan

			Switch ($_param.Name)
			{

				'ApplianceConnection'
				{

					$_CmdletParameter = New-ApplianceConnectionCmdletParameter

				}

				'Async'
				{

					$_CmdletParameter = New-AsyncCmdletParameter

				}

				'Credential'
				{

					$_CmdletParameter = New-PSCredentialCmdletParameter
				}

				'Scope'
				{

					$_CmdletParameter = New-ScopeCmdletParameter $_CmdletVerb

				}

				default
				{

					$_CmdletParameter                         = New-CmdletParameter
					$_CmdletParameter.Name                    = $_param.Name
					$_CmdletParameter.DefaultValue            = $_param.defaultValue

					if ($_param.type.name -eq 'switch')
					{
						
						$_CmdletParameter.ParameterValue.Value    = 'SwitchParameter'

					}

					else
					{
					
						$_CmdletParameter.ParameterValue.Value    = $_param.type.name	
					
					}
					
					$_CmdletParameter.ParameterValue.required = $_param.required

				}

			}

			[void]$_NewCmdletSkeleton.Contents.Parameters.Add($_CmdletParameter)

		}

	}

	$_DefaultCmdletExample = New-CmdletExample

	$_DefaultCmdletExample.Title = $_DefaultCmdletExample.Title -f '1'
	$_DefaultCmdletExample.Code  = "{0}`r`n" -f $_Command.Name

	[void]$_NewCmdletSkeleton.Contents.Examples.Add($_DefaultCmdletExample)
	
	$_DefaultRelatedLink = New-CmdletRelatedLink

	$_DefaultRelatedLink.URI  = "https://github.com/HewlettPackard/POSH-HPOneView/wiki/{0}" -f $_Command.Name.Clone()
	$_DefaultRelatedLink.Text = "Online Version:"

	[void]$_NewCmdletSkeleton.Contents.RelatedLinks.Add($_DefaultRelatedLink)

	$_CommandNoun = ($_Command.Name.Split('-'))[1]

	ForEach ($_relatedLink in ($_Commands | ? { $_.Name -match $_CommandNoun -and $_.Name -ne $_Command.Name }))
	{

		Write-Host ("-- Adding {0} related link" -f $_relatedLink.Name) -ForegroundColor Cyan

		$_NewRelatedLink = New-CmdletRelatedLink

		$_NewRelatedLink.URI  = $null
		$_NewRelatedLink.Text = $_relatedLink.Name.Clone()

		[void]$_NewCmdletSkeleton.Contents.RelatedLinks.Add($_NewRelatedLink)

	}

	return $_NewCmdletSkeleton

}

function New-CmdletParameter
{

	return [PSCustomObject]@{

		Name           = $null;
		Description    = 'default content';
		ParameterValue = [PSCustomObject]@{
			value    = $null;
			required = $false
		};
		DefaultValue   = $null
	}
				
}

function New-ApplianceConnectionCmdletParameter
{
	
	return [PSCustomObject]@{
		Name           = "ApplianceConnection";
		Description    = "Aliases [-Appliance]`n`nSpecify one or more HPOneView.Appliance.Connection object(s) or Name property value(s).`n`nDefault Value: `${Global:ConnectedSessions} | ? Default";
		ParameterValue = @{
			value    = "Array";
			required = $false
		};
		DefaultValue   = "(`${Global:ConnectedSessions} | ? Default)"

	}

}

function New-AsyncCmdletParameter
{

	return [PSCustomObject]@{

		Name           = "Async";
		Description    = "Use this parameter to immediately return the async task.  By default, the Cmdlet will wait for the task to complete.";
		ParameterValue = [PSCustomObject]@{
			value    = 'SwitchParameter';
			required = $false
		};
		DefaultValue   = $false
	}
	
}

function New-ScopeCmdletParameter ($_CmdletVerb)
{

	Switch ($_CmdletVerb)
	{

		'Get'
		{

			return [PSCustomObject]@{

				Name           = "Scope";
				Description    = "Filter resources based on provided Scope membership.  By default, all resources for the accounts Active Permissions will be displayed.  Allowed values:\r\n\r\n\t* AllResources\r\n\t*AllResourcesInScope\r\n\t* HPOneView.Appliance.ScopeCollection\r\n\t* HPOneView.Appliance.ConnectionPermission";
				ParameterValue = [PSCustomObject]@{
					value    = 'Object';
					required = $false
				};
				DefaultValue   = "AllResourcesInScope"
			}

		}

		{'New', 'Add' -contains $_}
		{

			return [PSCustomObject]@{

				Name           = "Scope";
				Description    = "Provide an HPOneView.Appliance.ScopeCollection resource object to initially associate with.  Resource can also be added to scope using the Add-HPOVResourceToScope Cmdlet.";
				ParameterValue = [PSCustomObject]@{
					value    = 'HPOneView.Appliance.ScopeCollection';
					required = $false
				};
				DefaultValue   = $false
			}

		}

	}	
	
}

function New-PSCredentialCmdletParameter
{

	return [PSCustomObject]@{

		Name           = "Credential";
		Description    = "Use this parameter if you want to provide a PSCredential object instead.";
		ParameterValue = [PSCustomObject]@{
			value    = 'PSCredential';
			required = $false
		};
		DefaultValue   = $null
	}
	
}

function New-CmdletReturnValue
{

	return [PSCustomObject]@{
		Value = $null;
		Text = $null
	
	}

}

function New-CmdletInputType
{

	return [PSCustomObject]@{
		Value = $null;
		Text = $null
	
	}

}

function New-CmdletExample
{

	return [PSCustomObject] @{
		Title = "-------------------------- EXAMPLE {0} --------------------------";
		Code = $null;
		Description = 'Default example'
	}
}

function New-CmdletRelatedOnlineLink
{

	return [PSCustomObject] @{
		URI = "https:/github.com/HewlettPackard/POSH-HPOneView/wiki/{0}";
		Text = "Online Version:"
	}

}

function New-CmdletRelatedLink
{

	return [PSCustomObject] @{
		URI = $null;
		Text = $null
	}

}

function Validate-XMLHelp 
{

    ipmo HPOneView.400

    [array]$commands = Get-Command -Module HPOneView.400 | ? Name -ne "prompt"

    Clear-Content C:\temp\command_help.txt -force -Confirm:$false

    $commands | % {

        write-host "Processing $($_.name)" -ForegroundColor Yellow

        "MODULENAME: $($_.ModuleName)" | out-file C:\temp\command_help.txt -Append

        (Get-Help $_.name) | out-file C:\temp\command_help.txt -Append

        "------------------------------------------------------------------------------ - " | out-file C:\temp\command_help.txt -Append

    }
    
    Write-Host
    Write-Host "Opening Notepad++..." -ForegroundColor Magenta
    Write-Host

    & "C:\Program Files (x86)\Notepad++\notepad++.exe" C:\temp\command_help.txt

    remove-module HPOneView.400

}

function New-CabinetFile 
{

    [CmdletBinding()]
    Param
	(

        [Parameter(HelpMessage="Target .CAB file name.", Position=0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias("FilePath")]
        [String] $Name,
 
        [Parameter(HelpMessage="File(s) to add to the .CAB.", Position=1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias("FullName")]
        [Array] $File,
 
        [Parameter(HelpMessage="Default intput / output path.", Position=2, Mandatory)]
        [AllowNull()]
        [String] $DestinationPath,
 
        [Parameter(HelpMessage="Do not overwrite any existing .cab file.")]
        [Switch] $NoClobber

    )
 
    Begin 
	{ 
    
        ## If $DestinationPath is blank, use the current directory by default
        if ($DestinationPath -eq $null) 
		{ 
			
			$DestinationPath = (Get-Location).Path 
		
		}

        Write-Verbose "New-CabinetFile using default path '$DestinationPath'."

        Write-Verbose "Creating target cabinet file '$(Join-Path $DestinationPath $Name)'."
 
        ## Test the -NoClobber switch
        if ($NoClobber) 
		{

            ## If file already exists then throw a terminating error
            if (Test-Path -Path (Join-Path $DestinationPath $Name)) { throw "Output file '$(Join-Path $DestinationPath $Name)' already exists."; }

        }
 
		$ddf = New-Object System.Collections.ArrayList

        ## Cab files require a directive file, see 'http://msdn.microsoft.com/en-us/library/bb417343.aspx#dir_file_syntax' for more info
        [void]$ddf.Add("; * * * MakeCAB Directive file")
        [void]$ddf.Add( "; ")
        [void]$ddf.Add( ".OPTION EXPLICIT")
        [void]$ddf.Add( ".Set CabinetNameTemplate = $Name")
        [void]$ddf.Add( ".Set DiskDirectory1 = $DestinationPath")
        [void]$ddf.Add( ".Set MaxDiskSize = 0")
        [void]$ddf.Add( ".Set Cabinet = on")
        [void]$ddf.Add( ".Set Compress = on")

        ## Redirect the auto-generated Setup.rpt and Setup.inf files to the temp directory
        [void]$ddf.Add(".Set RptFileName = $(Join-Path $ENV:TEMP "setup.rpt")")
        [void]$ddf.Add(".Set InfFileName = $(Join-Path $ENV:TEMP "setup.inf")")
 
        ## If -Verbose, echo the directive file
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{

            foreach ($ddfLine in $ddf) # -split [Environment]::NewLine) 
			{

                Write-Verbose $ddfLine

            }

        }

    }
 
    Process 
	{
   
        ## Enumerate all the files add to the cabinet directive file
        foreach ($fileToAdd in $File) 
		{
        
            ## Test whether the file is valid as given and is not a directory
            if (Test-Path $fileToAdd -PathType Leaf) 
			{

                Write-Verbose """$fileToAdd"""

                [void]$ddf.Add("""$fileToAdd""")

            }
            ## If not, try joining the $File with the (default) $DestinationPath
            elseif (Test-Path (Join-Path $DestinationPath $fileToAdd) -PathType Leaf) 
			{

                Write-Verbose """$(Join-Path $DestinationPath $fileToAdd)"""

                [void]$ddf.Add("""$(Join-Path $DestinationPath $fileToAdd)""")

            
			}

            else 
			{ 
				
				Write-Warning "File '$fileToAdd' is an invalid file or container object and has been ignored." 
			
			}

        }    
           
    }
 
    End 
	{
    
        $ddfFile = Join-Path $DestinationPath "$Name.ddf"

        $ddf | Out-File $ddfFile -Encoding ascii | Out-Null
 
        Write-Verbose "Launching 'MakeCab /F ""$ddfFile""'."

        $makeCab = Invoke-Expression "MakeCab /F ""$ddfFile"""
 
        ## If Verbose, echo the MakeCab response/output
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{

            ## Recreate the output as Verbose output
            foreach ($line in $makeCab -split [environment]::NewLine) 
			{

                if ($line.Contains("ERROR:")) { throw $line }

                else { Write-Verbose $line }

            }

        }
 
        ## Delete the temporary .ddf file
        Write-Verbose "Deleting the directive file '$ddfFile'."

        Remove-Item $ddfFile
 
        ## Return the newly created .CAB FileInfo object to the pipeline
        Get-Item (Join-Path $DestinationPath $Name)

    }

}

Function New-ZipFile
{
	
    [CmdletBinding()]
    Param
	(

        [Parameter(HelpMessage="Target .ZIP file name.", Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias("FilePath")]
        [String]$Name,
 
        [Parameter(HelpMessage="File(s) to add to the .ZIP.", Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Array]$Files

    )
 
    Begin 
	{ 

        Write-Verbose "Creating target ZIP file '$Name'."

        if (Test-Path $Name)
        {

            "Found '{0}'. Removing" -f $Name

            Remove-Item $Name -Force -Confirm:$false

        }

	}

	Process
	{

		#Load some assemblys. (No line break!)
		[void][System.Reflection.Assembly]::Load("WindowsBase, Version = 3.0.0.0, Culture = neutral, PublicKeyToken = 31bf3856ad364e35")

		#Create a zip file named "MyZipFile.zip". (No line break!)
		$ZipPackage = [System.IO.Packaging.ZipPackage]::Open($Name, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite)

		#For each file you want to add, we must extract the bytes and add them to a part of the zip file.
		ForEach ($file In $files)
		{

            if (-not($file -is [System.IO.FileInfo]))
            {

                $file = gci $file

            }

            $FileNameForUri = '/' + $file.Name

            #Get file 'URI' for the ZIP file to be created
            $partName = New-Object System.Uri($FileNameForUri, [System.UriKind]::Relative)
	   
			#Create each part. (No line break!)
			$part = $ZipPackage.CreatePart($partName, "application/zip", [System.IO.Packaging.CompressionOption]::NotCompressed)
	   
            #get bytes of the file, using ThreadSafe System.IO.FileStream
            [byte[]]$Readbuffer = New-Object byte[] $file.Length 
            $FileStream         = New-Object System.IO.FileStream($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)	
            [void]$FileStream.ReadAsync([byte[]]$Readbuffer, 0, [int]$file.Length)

            #Get ZipPackage Stream
			$stream = $part.GetStream()

            #Write bytes to ZipPackage stream
			$stream.Write($Readbuffer, 0, $file.Length)

            #close stream
			$stream.Close()

            $FileStream.Dispose()

		}

        $ZipPackage.Flush()
        $ZipPackage.Dispose()

		#Close the package when we're done.
		$ZipPackage.Close()

	}
	
	End
	{


	}


}

Convert-EmbeddedToXml 