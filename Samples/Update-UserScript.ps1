##############################################################################
# Update-UserScript.ps1
#
# This script can be used independently from the HPEOneView.530 library to
# parse a user script and update all legacy HPEOneView Cmdlet names from
# {VERB}-OV{Nound} to {VERB}-OV{NOUN}, and any reference to HPOneView to
# HPEOneView.
#
#  -Path is a paramter that will iterate through the provided script file.
#
#  -Replace is used to commit the changes.  By default, this script will display
#           only the changes it will make, and not save them.  Use this parameter
#           to save the results.
#
#   VERSION 1.0
#
# (C) Copyright 2013-2020 Hewlett Packard Enterprise Development LP
##############################################################################
<#
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
#>
##############################################################################

[CmdletBinding ()]
Param
(

    [Parameter (Mandatory, ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [System.IO.FileInfo]$Path,

    [Parameter (Mandatory = $false)]
    [Switch]$Replace

)

Process
{

    $CmdletSearchExpression   = [System.Text.RegularExpressions.Regex]::new("(?'CmdletVerb'add|copy|get|new|remove|set|show|wait|clear|connect|convert|convertto|disable|disconnect|enable|enter|exit|import|install|invoke|join|ping|pop|push|reset|restart|restore|save|search|send|start|stop|test|update)-(?'VendorPrefix'hpov)(?'CmdletNoun'[a-z]+)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $OtherBrandStyleSearchExp = [System.Text.RegularExpressions.Regex]::new("(?'Libraryname'HPEOneView\.)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $StringBuilder            = [System.Collections.ArrayList]::new()
    $File                     = [System.IO.StreamReader]::new($Path)
    $ReplacementString        = '${CmdletVerb}-OV${CmdletNoun}'
    $LibraryReplacementString = 'HPEOneView.'

    While (-not ($file.EndOfStream))
    {
        $line = $file.ReadLine()

        $UpdatedLine = $CmdletSearchExpression.Replace($line, $ReplacementString)
        $UpdatedLine = $OtherBrandStyleSearchExp.Replace($UpdatedLine, $LibraryReplacementString)

        [void]$StringBuilder.Add($UpdatedLine)

    }

    $file.Close()

    if ($PSBoundParameters.Keys -Contains 'Replace')
    {

        [System.IO.File]::WriteAllText($File, $StringBuilder.ToArray())

    }

    else
    {

        $StringBuilder

    }

}