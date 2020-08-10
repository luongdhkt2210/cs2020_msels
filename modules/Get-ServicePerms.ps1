﻿# Service Permission Checker
# Ben Turner @benpturner

<#
.Synopsis
    Service Permission Checker
.DESCRIPTION
	Service Permission Checker
.EXAMPLE
    PS C:\> Get-ServicePerms -Path C:\temp\
#>
$sploaded = $null
Function Get-ServicePerms {

if ($sploaded -ne "TRUE") {
    $script:sploaded = "TRUE"
    echo "Loading Assembly"
    $i = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAK47qFoAAAAAAAAAAOAAIiALATAAACQAAAAGAAAAAAAAwkMAAAAgAAAAYAAAAAAAEAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACgAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAHBDAABPAAAAAGAAALgDAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAwAAAA4QgAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAyCMAAAAgAAAAJAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAALgDAAAAYAAAAAQAAAAmAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAIAAAAACAAAAKgAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAACkQwAAAAAAAEgAAAACAAUAHC0AABwVAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABswBQBTAgAAAQAAEQNvDgAACnIBAABwbw8AAAomA28OAAAKcgEAAHBvEAAACm8RAAAKchEAAHBvEgAACiYDbw4AAApyAQAAcG8QAAAKbxEAAApyHwAAcG8SAAAKJhQKFAsCbxMAAAoTBDiRAQAAEgQoFAAAChMFFAoUCxEFGHMVAAAKFxfQJwAAASgWAAAKbxcAAApvGAAAChMGOA0BAAARBm8ZAAAKdBQAAAETB3I3AABwChuNDwAAASUWEQdvGgAACqIlF3I5AABwoiUYEQdvGwAACowwAAABoiUZcjkAAHCiJRoRB28cAAAKjDEAAAGiKB0AAAoKBnI9AABwbx4AAAoGckkAAHBvHgAACl8sEXJXAABwBnKTAABwKB8AAAoKBnI9AABwbx4AAAoGcqkAAHBvHgAACl8sEXJXAABwBnKTAABwKB8AAAoKBnLBAABwbx4AAAoGckkAAHBvHgAACl8sEXJXAABwBnKTAABwKB8AAAoKBnLBAABwbx4AAAoGcqkAAHBvHgAACl8sEXJXAABwBnKTAABwKB8AAAoKBwZy0wAAcCgfAAAKCxEGbyAAAAo65/7//94VEQZ1FQAAARMIEQgsBxEIbyEAAArc3gMm3gADbw4AAApyAQAAcG8QAAAKbyIAAAoYjQ8AAAElFhEFoiUXB6JvIwAACiYSBCgkAAAKOmP+///eDhIE/hYCAAAbbyEAAArcKCUAAAomA28OAAAKct8AAHBvEAAACigDAAAGDANvDgAACnIBAABwbxAAAAooBAAABg1y8QAAcAgJKCYAAAooJwAACioAQUwAAAIAAACPAAAAIAEAAK8BAAAVAAAAAAAAAAAAAABvAAAAVwEAAMYBAAADAAAADwAAAQIAAABdAAAApAEAAAECAAAOAAAAAAAAABswCAAjBQAAAgAAESglAAAKJnMoAAAKJnMoAAAKCnMpAAAKCwdvDgAACnLfAABwbw8AAAomB28OAAAKct8AAHBvEAAACm8RAAAKchkBAHBvEgAACiYHbw4AAApy3wAAcG8QAAAKbxEAAApyMwEAcG8SAAAKJgdvDgAACnLfAABwbxAAAApvEQAACnJFAQBwbxIAAAomB28OAAAKct8AAHBvEAAACm8RAAAKch8AAHBvEgAACiYHbw4AAApy3wAAcG8QAAAKbxEAAApyWQEAcG8SAAAKJnKBAQBwcyoAAApzKwAACm8sAAAKby0AAAoMOBwEAAAIby4AAAp0GAAAAQ1yNwAAcBMECXK5AQBwby8AAApvMAAACnI3AABwKDEAAAosBd3oAwAACXK5AQBwby8AAApvMAAAChME3gMm3gByNwAAcBMFcjcAAHATBhEEcssBAHAXKDIAAAoTBxEHbzMAAAo5qAMAABEHbzQAAAoXbzUAAApvNgAACnLhAQBwKCYAAAoTCBEIcusBAHBvHgAACi0XEQhyOQAAcG8eAAAKLAly7wEAcBMGKwdyBQIAcBMGEQdvNAAAChdvNQAACm82AAAKcuEBAHAoJgAAChMFEQVy6wEAcHI3AABwbzcAAAoTBRQTCRQTChEFGHMVAAAKEQVzOAAACiYXF9AnAAABKBYAAApvFwAACm8YAAAKEw84IgEAABEPbxkAAAp0FAAAARMQcjcAAHATChuNDwAAASUWERBvGgAACqIlF3I5AABwoiUYERBvGwAACowwAAABoiUZcjkAAHCiJRoREG8cAAAKjDEAAAGiKB0AAAoTChEKcj0AAHBvHgAAChEKckkAAHBvHgAACl8sE3JXAABwEQpykwAAcCgfAAAKEwoRCnI9AABwbx4AAAoRCnKpAABwbx4AAApfLBNyVwAAcBEKcpMAAHAoHwAAChMKEQpywQAAcG8eAAAKEQpySQAAcG8eAAAKXywTclcAAHARCnKTAABwKB8AAAoTChEKcsEAAHBvHgAAChEKcqkAAHBvHgAACl8sE3JXAABwEQpykwAAcCgfAAAKEwoRCREKctMAAHAoHwAAChMJEQ9vIAAACjrS/v//3hURD3UVAAABExERESwHERFvIQAACtzeFiZyEQIAcBEFcjMCAHAoHwAAChMJ3gARBXI3AgBwFygyAAAKEwsRC28zAAAKLBMRC280AAAKF281AAAKbzAAAAomEQVzOAAACm85AAAKEwwrOQYRDG86AAAKbzAAAApvOwAACm88AAAKLRcGEQxvOgAACm8wAAAKbzsAAApvPQAAChEMbz4AAAoTDBEMLcNyNwAAcBMNCXJhAgBwby8AAApvMAAACnM/AAAKEw4RDm9AAAAKExUSFf4WHAAAAW8wAAAKEw0RDm9BAAAKExIRDm9CAAAKExMRDm9DAAAKExQdjTIAAAElFhENoiUXcmsCAHCiJRgSEihEAAAKoiUZcp0CAHCiJRoSEyhEAAAKoiUbcrkCAHCiJRwSFChEAAAKoihFAAAKEw3eFRMWctsCAHARFihGAAAKKEcAAAreAAdvDgAACnLfAABwbxAAAApvIgAAChuNDwAAASUWCXLnAgBwby8AAApvMAAACnL/AgBwCXJhAgBwby8AAApvMAAACnIFAwBwKEgAAAqiJRcRBqIlGAlyuQEAcG8vAAAKbzAAAAqiJRkRCaIlGhENom8jAAAKJghvSQAACjrZ+///3goILAYIbyEAAArcBgcoAQAABioAQXwAAAAAAAD7AAAANQAAADABAAADAAAADwAAAQIAAAAFAgAANQEAADoDAAAVAAAAAAAAAAAAAADdAQAAdAEAAFEDAAAWAAAADwAAAQAAAAD9AwAAfQAAAHoEAAAVAAAAHQAAAQIAAADjAAAALgQAABEFAAAKAAAAAAAAABswAwAMAgAAAwAAEQItC3IJAwBwc0oAAAp6c0sAAAoKBnIhAwBwb0wAAAomBnIvAwBwb0wAAAomBnI9AwBwb0wAAAomBnJNAwBwb0wAAAomBihNAAAKCxIB/hYgAAABbzAAAApvTAAACiYGclkDAHBvTAAACiYGcmsDAHBvTAAACiYGcnsDAHBvTAAACiYGcokDAHBvTAAACiYGciwEAHBvTAAACiYGcpYEAHBvTAAACiYGcv4EAHBvTAAACiYCbxEAAApvTgAACgwrMQhvGQAACnQhAAABDQZyPAUAcG9MAAAKJgYJb08AAApvTAAACiYGcnoFAHBvTAAACiYIbyAAAAotx94UCHUVAAABEwQRBCwHEQRvIQAACtwGcoYFAHBvTAAACiYCbyIAAApvTgAACgw4lAAAAAhvGQAACnQiAAABEwUGcv4EAHBvTAAACiYCbxEAAApvTgAAChMGK0ARBm8ZAAAKdCEAAAETBwZyPAUAcG9MAAAKJgYRBREHb08AAApvUAAACm8wAAAKb0wAAAomBnJ6BQBwb0wAAAomEQZvIAAACi233hURBnUVAAABEwQRBCwHEQRvIQAACtwGcoYFAHBvTAAACiYIbyAAAAo6Yf///94UCHUVAAABEwQRBCwHEQRvIQAACtwGcpIFAHBvTAAACiYGcqQFAHBvTAAACiYGcrQFAHBvTAAACiYGbzAAAAoqASgAAAIAvgA9+wAUAAAAAAIAUgFNnwEVAAAAAAIAJwGmzQEUAAAAABswAwAAAgAAAwAAEQItC3IJAwBwc0oAAAp6c0sAAAoKBnIhAwBwb0wAAAomBnIvAwBwb0wAAAomBnI9AwBwb0wAAAomBnJNAwBwb0wAAAomBihNAAAKCxIB/hYgAAABbzAAAApvTAAACiYGclkDAHBvTAAACiYGcmsDAHBvTAAACiYGcnsDAHBvTAAACiYGciwEAHBvTAAACiYGcpYEAHBvTAAACiYGcv4EAHBvTAAACiYCbxEAAApvTgAACgwrMQhvGQAACnQhAAABDQZyPAUAcG9MAAAKJgYJb08AAApvTAAACiYGcnoFAHBvTAAACiYIbyAAAAotx94UCHUVAAABEwQRBCwHEQRvIQAACtwGcoYFAHBvTAAACiYCbyIAAApvTgAACgw4lAAAAAhvGQAACnQiAAABEwUGcv4EAHBvTAAACiYCbxEAAApvTgAAChMGK0ARBm8ZAAAKdCEAAAETBwZyPAUAcG9MAAAKJgYRBREHb08AAApvUAAACm8wAAAKb0wAAAomBnJ6BQBwb0wAAAomEQZvIAAACi233hURBnUVAAABEwQRBCwHEQRvIQAACtwGcoYFAHBvTAAACiYIbyAAAAo6Yf///94UCHUVAAABEwQRBCwHEQRvIQAACtwGcpIFAHBvTAAACiYGcqQFAHBvTAAACiYGcrQFAHBvTAAACiYGbzAAAAoqASgAAAIAsgA97wAUAAAAAAIARgFNkwEVAAAAAAIAGwGmwQEUAAAAAEJTSkIBAAEAAAAAAAwAAAB2Mi4wLjUwNzI3AAAAAAUAbAAAAAAFAAAjfgAAbAUAAIwHAAAjU3RyaW5ncwAAAAD4DAAAxAUAACNVUwC8EgAAEAAAACNHVUlEAAAAzBIAAFACAAAjQmxvYgAAAAAAAAACAAABRxUCCAkAAAAA+gEzABYAAAEAAABDAAAAAgAAAAQAAAAEAAAAUAAAAA0AAAADAAAAAgAAAAEAAAAFAAAAAAAvAwEAAAAAAAYAWQI/BQYAxgI/BQYApgEKBQ8AbAUAAAYAzgGcAwYAPAKcAwYAHQKcAwYArQKcAwYAeQKcAwYAkgKcAwYA5QGcAwYAugEgBQYAmAEgBQYAAAKcAwYAuAaCAwYAAQBIAAoAzgYzAEMA+QQAAAYAzwQEBgYA+QBbAwYAqgCCAw4AAwTWBlsA2wQAAA4ArgbWBhIADwPPBQYAbgQpABYAtQQ7BhYAcQY7BgYAPASCAwoAlAAzAAYAjgQdBwYAagCCAwoAkQMzAAoANgczAAoArgMzAAoA3gMzAAYAagdbAwYA7gVbAwYA/wYVAwYAUQGCAwYAtgCCAwYAdwdbAwYAwgNbAwYAeQEEBgYA5wBbAwYAggAVAwYAAwFbAwYARAFbAwYAVQZbAwYACAOCAwoAHgQzABIAtgXDBgYA2gApAA4ARAfWBg4AnATWBg4AmQbWBhIAPgfPBRIAFwbPBRIAiATPBRIA8wPPBRIAVgHPBQYAVgQpAAYAXwQpAAYAiQOCAwYA3wCCAwYAMASCAwoAXgEzAAAAAAAgAAAAAAABAAEAgQEQAJkFAAA9AAEAAQBQIAAAAACWAKYFnAEBAPwiAAAAAJYAXwWnAQMAqCgAAAAAlgBEA6sBAwDoKgAAAACWAAgAqwEEAAAAAQAJBwAAAgAdBQAAAQCeAAAAAQCeAAkABAUBABEABAUGABkABAUKACkABAUQADEABAUQADkABAUQAEEABAUQAEkABAUQAFEABAUQAFkABAUQAGEABAUVAGkABAUQAHEABAUQAIkAewUtABkBYwAzABkBeQMzAPEAwwU5ACEBYwA/AAwA9gRMABQA8wZbACkBBAVgAEEByABoAFEBhgVxAGEB9gR8AJkA8waBAGkBfgCFAHkBQAGLAKEAUQaRAJEBkgaXAJEBugWdAJEBkgaiAJkAFAepAKkAkAEGAPEAiQatAJkBYwCzABQAFAepAKEBKgG7AJEBkga/AKkBKQfFAAwABAUGAIkABAUGALEBBAUQALkBBAX1ALkBvwb8ALEA9gQBAbkA8wYGAcEBeQMMAXkABgMRAZEBXgcVAckBDwMbAdkBLwapAMkAJAYlAeEBeQMrAekB5AIRAZEBdgAyAfEBBAUQAPEBUAc4AfkBDgERAZEBxwQRAQwAugU9AQwAYwBDAdEA6AY4AdkABAUQANkAZgZJAdkA7gKpANkAfASpANkARgSpAAECBgMRAZEBkgZOAZEBkgZUAQkCNgFaAZEBkgZfAbkAFAepABECBAUQAPkABAUGAPkAbwB+AQEBZwCEARkC9gR8AAkBGwERAREBeQMMAS4ACwCxAS4AEwC6AS4AGwDZAS4AIwDiAS4AKwD4AS4AMwD4AS4AOwD4AS4AQwDiAS4ASwD+AS4AUwD4AS4AWwD4AS4AYwAWAi4AawBAAhoAywBnAUYAVQAEgAAAAQAAAAAAAAAAAAAAAACVBQAAAgAAAAAAAAAAAAAAigE/AAAAAAACAAAAAAAAAAAAAACKATMAAAAAAAIAAAAAAAAAAAAAAJMB1gYAAAAAAgAAAAAAAAAAAAAAigGCAwAAAAACAAAAAAAAAAAAAACTATsGAAAAAAAAAExpc3RgMQBDb252ZXJ0RGF0YVRhYmxlVG9IdG1sMgA8TW9kdWxlPgBTeXN0ZW0uSU8AU3lzdGVtLkRhdGEAbXNjb3JsaWIAU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMAQWRkAE5ld0d1aWQAQXBwZW5kAFJlcGxhY2UAZ2V0X0lkZW50aXR5UmVmZXJlbmNlAERhdGFUYWJsZQB0YXJnZXRUYWJsZQBJRGlzcG9zYWJsZQBSdW50aW1lVHlwZUhhbmRsZQBHZXRUeXBlRnJvbUhhbmRsZQBGaWxlAENvbnNvbGUAQXV0aG9yaXphdGlvblJ1bGUARmlsZVN5c3RlbUFjY2Vzc1J1bGUAZ2V0X0Z1bGxOYW1lAGdldF9Db2x1bW5OYW1lAEdldEhvc3ROYW1lAFdyaXRlTGluZQBnZXRfQWNjZXNzQ29udHJvbFR5cGUAQ2FwdHVyZQBJbnRlcm5hbERhdGFDb2xsZWN0aW9uQmFzZQBSZWFkT25seUNvbGxlY3Rpb25CYXNlAERpc3Bvc2UAR3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBnZXRfVmFsdWUAZ2V0X0NhblBhdXNlQW5kQ29udGludWUAVG9TdHJpbmcATWF0Y2gAU3lzdGVtLlNlY3VyaXR5LlByaW5jaXBhbABHZXQtU2VydmljZVBlcm1zLmRsbABDb252ZXJ0RGF0YVRhYmxlVG9IdG1sAFN5c3RlbS5TZWN1cml0eS5BY2Nlc3NDb250cm9sAGdldF9JdGVtAFN5c3RlbQBCb29sZWFuAERhdGFDb2x1bW4AU3lzdGVtLlJlZmxlY3Rpb24ARGF0YVRhYmxlQ29sbGVjdGlvbgBBdXRob3JpemF0aW9uUnVsZUNvbGxlY3Rpb24ARGF0YUNvbHVtbkNvbGxlY3Rpb24AR3JvdXBDb2xsZWN0aW9uAE1hbmFnZW1lbnRPYmplY3RDb2xsZWN0aW9uAERhdGFSb3dDb2xsZWN0aW9uAEFyZ3VtZW50TnVsbEV4Y2VwdGlvbgBnZXRfQ2FuU2h1dGRvd24ARmlsZUluZm8ARmlsZVN5c3RlbUluZm8ARGlyZWN0b3J5SW5mbwBnZXRfQ2FuU3RvcABHcm91cABTdHJpbmdCdWlsZGVyAE1hbmFnZW1lbnRPYmplY3RTZWFyY2hlcgBTZXJ2aWNlQ29udHJvbGxlcgBUb0xvd2VyAElFbnVtZXJhdG9yAE1hbmFnZW1lbnRPYmplY3RFbnVtZXJhdG9yAEdldEVudW1lcmF0b3IALmN0b3IAU3lzdGVtLkRpYWdub3N0aWNzAGRzAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAGR1bXBzZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBnZXRfVGFibGVzAEdldEFjY2Vzc1J1bGVzAEdldC1TZXJ2aWNlUGVybXMAZHVtcGZvbGRlcnBlcm1zAERucwBDb250YWlucwBnZXRfQ29sdW1ucwBTeXN0ZW0uVGV4dC5SZWd1bGFyRXhwcmVzc2lvbnMAQWNjZXNzQ29udHJvbFNlY3Rpb25zAFN5c3RlbS5Db2xsZWN0aW9ucwBSZWdleE9wdGlvbnMAZ2V0X0dyb3VwcwBnZXRfU3VjY2VzcwBTeXN0ZW0uU2VydmljZVByb2Nlc3MAZ2V0X0ZpbGVTeXN0ZW1SaWdodHMAZ2V0X1N0YXR1cwBTZXJ2aWNlQ29udHJvbGxlclN0YXR1cwBnZXRfUm93cwBDb25jYXQATWFuYWdlbWVudEJhc2VPYmplY3QATWFuYWdlbWVudE9iamVjdABHZXQAU3lzdGVtLk5ldABEYXRhU2V0AFN5c3RlbS5NYW5hZ2VtZW50AGdldF9QYXJlbnQAZ2V0X0N1cnJlbnQATlRBY2NvdW50AGZvbGRlcmxpc3QATW92ZU5leHQAU3lzdGVtLlRleHQAV3JpdGVBbGxUZXh0AERhdGFSb3cAUmVnZXgAT2JqZWN0UXVlcnkAZ2V0X0RpcmVjdG9yeQBvcF9FcXVhbGl0eQBGaWxlU2VjdXJpdHkAQ29tbW9uT2JqZWN0U2VjdXJpdHkAAA9mAG8AbABkAGUAcgBzAAANRgBvAGwAZABlAHIAABdQAGUAcgBtAGkAcwBzAGkAbwBuAHMAAAEAAyAAAAtVAHMAZQByAHMAAA1NAG8AZABpAGYAeQAAOzwAYgA+ADwAZABpAHYAIABzAHQAeQBsAGUAPQAiAGMAbwBsAG8AcgA6AHIAZQBkADsAIgA+ACoAKgAAFTwALwBkAGkAdgA+ADwALwBiAD4AABdGAHUAbABsAEMAbwBuAHQAcgBvAGwAABFFAHYAZQByAHkAbwBuAGUAAAsgADwAYgByAD4AABFzAGUAcgB2AGkAYwBlAHMAACdDADoAXABUAGUAbQBwAFwAUgBlAHAAbwByAHQALgBoAHQAbQBsAAAZUwBlAHIAdgBpAGMAZQAgAE4AYQBtAGUAABFVAG4AcQB1AG8AdABlAGQAABNJAG0AYQBnAGUAUABhAHQAaAAAJ1MAZQByAHYAaQBjAGUAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AADdTAEUATABFAEMAVAAgACoAIABGAFIATwBNACAAVwBpAG4AMwAyAF8AUwBlAHIAdgBpAGMAZQAAEVAAYQB0AGgATgBhAG0AZQAAFV4AKAAuACsAPwApAC4AZQB4AGUAAAkuAGUAeABlAAADIgAAFVUAbgBxAHUAbwB0AGUAZAAqACoAAAtGAGEAbABzAGUAACFQAGEAdABoACAAbgBvAHQAIABmAG8AdQBuAGQAOgAgAAADCgAAKV4AKAAuACoAWwBcAFwAXAAvAF0AKQBbAF4AXABcAFwALwBdACoAJAAACU4AYQBtAGUAADE8AGIAcgA+AEMAYQBuAFAAYQB1AHMAZQBBAG4AZABDAG8AbgB0AGkAbgB1AGUAOgAAGzwAYgByAD4AQwBhAG4AUwB0AGEAcgB0ADoAACE8AGIAcgA+AEMAYQBuAFMAaAB1AHQAZABvAHcAbgA6AAALRQByAHIAbwByAAAXRABpAHMAcABsAGEAeQBOAGEAbQBlAAAFIAAoAAADKQAAF3QAYQByAGcAZQB0AFQAYQBiAGwAZQAADTwAaAB0AG0AbAA+AAANPABoAGUAYQBkAD4AAA88AHQAaQB0AGwAZQA+AAALUABhAGcAZQAtAAERPAAvAHQAaQB0AGwAZQA+AAAPPAAvAGgAZQBhAGQAPgAADTwAYgBvAGQAeQA+AACAoTwAaAAx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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    $dllbytes  = [System.Convert]::FromBase64String($i)
    $assembly = [System.Reflection.Assembly]::Load($dllbytes)
}

[ServicePerms]::dumpservices()
$computer = $env:COMPUTERNAME
$complete = "[+] Writing output to C:\Temp\Report.html"
echo "[+] Completed Service Permissions Review"
echo "$complete"

}