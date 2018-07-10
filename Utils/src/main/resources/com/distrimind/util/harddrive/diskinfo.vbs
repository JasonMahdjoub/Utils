ComputerName = "."
Set wmiServices  = GetObject ( _
    "winmgmts:{impersonationLevel=Impersonate}!//" _
    & ComputerName)
' Get physical disk drive
Set wmiDiskDrives =  wmiServices.ExecQuery ( "SELECT Caption, DeviceID, Size, InterfaceType, SerialNumber FROM Win32_DiskDrive")

For Each wmiDiskDrive In wmiDiskDrives
   ' x = wmiDiskDrive.Caption & Vbtab & " " & wmiDiskDrive.DeviceID
    'Use the disk drive device id to
    ' find associated partition
    query = "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" & wmiDiskDrive.DeviceID & "'} WHERE AssocClass = Win32_DiskDriveToDiskPartition"
    Set wmiDiskPartitions = wmiServices.ExecQuery(query)
	Wscript.Echo wmiDiskDrive.DeviceID
    For Each wmiDiskPartition In wmiDiskPartitions
        'Use partition device id to find logical disk

        Set wmiLogicalDisks = wmiServices.ExecQuery ("ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" _
             & wmiDiskPartition.DeviceID & "'} WHERE AssocClass = Win32_LogicalDiskToPartition")

        For Each wmiLogicalDisk In wmiLogicalDisks
			If IsNull(wmiLogicalDisk.DeviceID) OR wmiLogicalDisk.DeviceID="" Then
				deviceID="_"
			Else
				deviceID=wmiLogicalDisk.DeviceID
			End If
			If IsNull(wmiLogicalDisk.FreeSpace) OR wmiLogicalDisk.FreeSpace="" Then
				freeSpace=-1
			Else
				freeSpace=wmiLogicalDisk.FreeSpace
			End If

			If wmiLogicalDisk.DriveType OR wmiLogicalDisk.DriveType="" Then
				driveType="_"
			Else
				driveType=Replace(wmiLogicalDisk.DriveType, " ", "_")
			End If
			If IsNull(wmiLogicalDisk.Size) OR wmiLogicalDisk.Size="" Then
				volumeSize="-1"
			Else
				volumeSize=wmiLogicalDisk.Size
			End If
			If IsNull(wmiLogicalDisk.BlockSize) OR wmiLogicalDisk.BlockSize="" Then
				volumeBlockSize="-1"
			Else
				volumeBlockSize=wmiLogicalDisk.BlockSize
			End If


			If IsNull(wmiLogicalDisk.VolumeName) OR wmiLogicalDisk.VolumeName="" Then
				name="_"
			Else
				name=Replace(wmiLogicalDisk.VolumeName, " ", "_")
			End If
			If IsNull(wmiLogicalDisk.FileSystem) OR wmiLogicalDisk.FileSystem="" Then
				fileSystem="_"
			Else
				fileSystem=Replace(wmiLogicalDisk.FileSystem, " ", "_")
			End If
			If IsNull(wmiDiskDrive.Caption) OR wmiDiskDrive.Caption="" Then
				caption="_"
			Else
				caption=Replace(wmiDiskDrive.Caption, " ", "_")
			End If
			If IsNull(wmiDiskDrive.DeviceID) OR wmiDiskDrive.DeviceID="" Then
				diskID="_"
			Else
				diskID=wmiDiskDrive.DeviceID
			End If
			If IsNull(wmiDiskDrive.InterfaceType) OR wmiDiskDrive.InterfaceType="" Then
				interfaceType="_"
			Else
				interfaceType=Replace(wmiDiskDrive.InterfaceType, " ", "_")
			End If
			If IsNull(wmiDiskDrive.Size) OR wmiDiskDrive.Size="" Then
				diskSize="-1"
			Else
				diskSize=wmiDiskDrive.Size
			End If
			If IsNull(wmiDiskDrive.SerialNumber) OR wmiDiskDrive.SerialNumber="" Then
				serialNumber="-1"
			Else
				serialNumber=wmiDiskDrive.SerialNumber
			End If

			Wscript.Echo deviceID & " " & name & " " & fileSystem & " " & volumeSize & " " & freeSpace & " " & volumeBlockSize & " " & caption & " " & diskID & " " & diskSize & " " & interfaceType & " " & serialNumber



        Next
    Next
Next


Set objFSO = CreateObject("Scripting.FileSystemObject")
Set colDrives = objFSO.Drives
For Each objDrive In colDrives
	isReady = "0"
	If(objDrive.IsReady) Then
		isReady="1"
	End If
	If IsNull(objDrive.DriveType) OR objDrive.DriveType="" Then
		driveType="_"
	Else
		driveType=objDrive.DriveType
	End If
	If IsNull(objDrive.FileSystem) OR objDrive.FileSystem="" Then
		fileSystem="_"
	Else
		fileSystem=Replace(objDrive.FileSystem, " ", "_")
	End If
	If IsNull(objDrive.TotalSize) OR objDrive.TotalSize="" Then
		totalSize="-1"
	Else
		totalSize=objDrive.TotalSize
	End If
	If IsNull(objDrive.FreeSpace) OR objDrive.FreeSpace="" Then
		freeSpace="-1"
	Else
		freeSpace=objDrive.FreeSpace
	End If
	If IsNull(objDrive.VolumeName) OR objDrive.VolumeName="" Then
    		volumeName="_"
    	Else
    		volumeName=objDrive.VolumeName
    	End If
	If Not IsNull(objDrive.DriveLetter) Then
		Wscript.Echo objDrive.DriveLetter & " " & objDrive.SerialNumber & " " & driveType & " " & fileSystem & " " & totalSize & " " & freeSpace & " " & isReady & " " & volumeName
	End If
Next