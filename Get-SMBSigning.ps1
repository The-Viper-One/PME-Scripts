Function Get-SMBSigning  {

Param (
    [String]$Target,
    [String[]]$Targets=@(),
    [Float]$Delay,
    [Float]$DelayJitter
    ) 

    #borrowed from https://github.com/Kevin-Robertson/Inveigh/blob/master/Scripts/Inveigh-Relay.ps1
    function ConvertFrom-PacketOrderedDictionary
    {
        param($packet_ordered_dictionary)

        ForEach($field in $packet_ordered_dictionary.Values)
        {
            $byte_array += $field
        }

        return $byte_array
    }

    #NetBIOS

    function Get-PacketNetBIOSSessionService()
    {
        param([Int]$packet_header_length,[Int]$packet_data_length)

        [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_header_length + $packet_data_length)
        $packet_NetBIOS_session_service_length = $packet_netbios_session_service_length[2..0]

        $packet_NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Message_Type",[Byte[]](0x00))
        $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Length",[Byte[]]($packet_netbios_session_service_length))

        return $packet_NetBIOSSessionService
    }

    #SMB1

    function Get-PacketSMBHeader()
    {
        param([Byte[]]$packet_command,[Byte[]]$packet_flags,[Byte[]]$packet_flags2,[Byte[]]$packet_tree_ID,[Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID)

        $packet_SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBHeader.Add("SMBHeader_Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
        $packet_SMBHeader.Add("SMBHeader_Command",$packet_command)
        $packet_SMBHeader.Add("SMBHeader_ErrorClass",[Byte[]](0x00))
        $packet_SMBHeader.Add("SMBHeader_Reserved",[Byte[]](0x00))
        $packet_SMBHeader.Add("SMBHeader_ErrorCode",[Byte[]](0x00,0x00))
        $packet_SMBHeader.Add("SMBHeader_Flags",$packet_flags)
        $packet_SMBHeader.Add("SMBHeader_Flags2",$packet_flags2)
        $packet_SMBHeader.Add("SMBHeader_ProcessIDHigh",[Byte[]](0x00,0x00))
        $packet_SMBHeader.Add("SMBHeader_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMBHeader.Add("SMBHeader_Reserved2",[Byte[]](0x00,0x00))
        $packet_SMBHeader.Add("SMBHeader_TreeID",$packet_tree_ID)
        $packet_SMBHeader.Add("SMBHeader_ProcessID",$packet_process_ID)
        $packet_SMBHeader.Add("SMBHeader_UserID",$packet_user_ID)
        $packet_SMBHeader.Add("SMBHeader_MultiplexID",[Byte[]](0x00,0x00))

        return $packet_SMBHeader
    }

    function Get-PacketSMBNegotiateProtocolRequest()
    {
        param([String]$packet_version)

        if($packet_version -eq "SMB1")
        {
            [Byte[]]$packet_byte_count = 0x0c,0x00
        }
        else
        {
            [Byte[]]$packet_byte_count = 0x22,0x00  
        }

        $packet_SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_WordCount",[Byte[]](0x00))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_ByteCount",$packet_byte_count)
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

        if($packet_version -ne "SMB1")
        {
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
        }

        return $packet_SMBNegotiateProtocolRequest
    }

    function Get-PacketSMBSessionSetupAndXRequest()
    {
        param([Byte[]]$packet_security_blob)

        [Byte[]]$packet_byte_count = [System.BitConverter]::GetBytes($packet_security_blob.Length)
        $packet_byte_count = $packet_byte_count[0,1]
        [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length + 5)
        $packet_security_blob_length = $packet_security_blob_length[0,1]

        $packet_SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_WordCount",[Byte[]](0x0c))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_MaxBuffer",[Byte[]](0xff,0xff))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_MaxMpxCount",[Byte[]](0x02,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_VCNumber",[Byte[]](0x01,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SecurityBlobLength",$packet_byte_count)
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_ByteCount",$packet_security_blob_length)
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SecurityBlob",$packet_security_blob)
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_NativeOS",[Byte[]](0x00,0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_NativeLANManage",[Byte[]](0x00,0x00))

        return $packet_SMBSessionSetupAndXRequest 
    }

    function Get-PacketSMBTreeConnectAndXRequest()
    {
        param([Byte[]]$packet_path)

        [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length + 7)
        $packet_path_length = $packet_path_length[0,1]

        $packet_SMBTreeConnectAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_WordCount",[Byte[]](0x04))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Flags",[Byte[]](0x00,0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_PasswordLength",[Byte[]](0x01,0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_ByteCount",$packet_path_length)
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Password",[Byte[]](0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Tree",$packet_path)
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Service",[Byte[]](0x3f,0x3f,0x3f,0x3f,0x3f,0x00))

        return $packet_SMBTreeConnectAndXRequest
    }

    function Get-PacketSMBNTCreateAndXRequest()
    {
        param([Byte[]]$packet_named_pipe)

        [Byte[]]$packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
        $packet_named_pipe_length = $packet_named_pipe_length[0,1]
        [Byte[]]$packet_file_name_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length - 1)
        $packet_file_name_length = $packet_file_name_length[0,1]

        $packet_SMBNTCreateAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_WordCount",[Byte[]](0x18))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Reserved2",[Byte[]](0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_FileNameLen",$packet_file_name_length)
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_CreateFlags",[Byte[]](0x16,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_RootFID",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AllocationSize",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_FileAttributes",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_ShareAccess",[Byte[]](0x07,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Disposition",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_CreateOptions",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_SecurityFlags",[Byte[]](0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_ByteCount",$packet_named_pipe_length)
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Filename",$packet_named_pipe)

        return $packet_SMBNTCreateAndXRequest
    }

    function Get-PacketSMBReadAndXRequest()
    {
        $packet_SMBReadAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_WordCount",[Byte[]](0x0a))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_FID",[Byte[]](0x00,0x40))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_MaxCountLow",[Byte[]](0x58,0x02))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_MinCount",[Byte[]](0x58,0x02))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Unknown",[Byte[]](0xff,0xff,0xff,0xff))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Remaining",[Byte[]](0x00,0x00))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBReadAndXRequest
    }

    function Get-PacketSMBWriteAndXRequest()
    {
        param([Byte[]]$packet_file_ID,[Int]$packet_RPC_length)

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length)
        $packet_write_length = $packet_write_length[0,1]

        $packet_SMBWriteAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_WordCount",[Byte[]](0x0e))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_FID",$packet_file_ID)
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Offset",[Byte[]](0xea,0x03,0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Reserved2",[Byte[]](0xff,0xff,0xff,0xff))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_WriteMode",[Byte[]](0x08,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Remaining",$packet_write_length)
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataLengthHigh",[Byte[]](0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataLengthLow",$packet_write_length)
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataOffset",[Byte[]](0x3f,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_HighOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_ByteCount",$packet_write_length)

        return $packet_SMBWriteAndXRequest
    }

    function Get-PacketSMBCloseRequest()
    {
        param ([Byte[]]$packet_file_ID)

        $packet_SMBCloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBCloseRequest.Add("SMBCloseRequest_WordCount",[Byte[]](0x03))
        $packet_SMBCloseRequest.Add("SMBCloseRequest_FID",$packet_file_ID)
        $packet_SMBCloseRequest.Add("SMBCloseRequest_LastWrite",[Byte[]](0xff,0xff,0xff,0xff))
        $packet_SMBCloseRequest.Add("SMBCloseRequest_ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBCloseRequest
    }

    function Get-PacketSMBTreeDisconnectRequest()
    {
        $packet_SMBTreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBTreeDisconnectRequest.Add("SMBTreeDisconnectRequest_WordCount",[Byte[]](0x00))
        $packet_SMBTreeDisconnectRequest.Add("SMBTreeDisconnectRequest_ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBTreeDisconnectRequest
    }

    function Get-PacketSMBLogoffAndXRequest()
    {
        $packet_SMBLogoffAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_WordCount",[Byte[]](0x02))
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBLogoffAndXRequest
    }

    #SMB2

    function Get-PacketSMB2Header()
    {
        param([Byte[]]$packet_command,[Int]$packet_message_ID,[Byte[]]$packet_tree_ID,[Byte[]]$packet_session_ID)

        [Byte[]]$packet_message_ID = [System.BitConverter]::GetBytes($packet_message_ID) + 0x00,0x00,0x00,0x00

        $packet_SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2Header.Add("SMB2Header_ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
        $packet_SMB2Header.Add("SMB2Header_StructureSize",[Byte[]](0x40,0x00))
        $packet_SMB2Header.Add("SMB2Header_CreditCharge",[Byte[]](0x01,0x00))
        $packet_SMB2Header.Add("SMB2Header_ChannelSequence",[Byte[]](0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_Reserved",[Byte[]](0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_Command",$packet_command)
        $packet_SMB2Header.Add("SMB2Header_CreditRequest",[Byte[]](0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_Flags",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_MessageID",$packet_message_ID)
        $packet_SMB2Header.Add("SMB2Header_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_TreeID",$packet_tree_ID)
        $packet_SMB2Header.Add("SMB2Header_SessionID",$packet_session_ID)
        $packet_SMB2Header.Add("SMB2Header_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        return $packet_SMB2Header
    }

    function Get-PacketSMB2NegotiateProtocolRequest()
    {
        $packet_SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_StructureSize",[Byte[]](0x24,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_DialectCount",[Byte[]](0x02,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_SecurityMode",[Byte[]](0x01,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved",[Byte[]](0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextCount",[Byte[]](0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved2",[Byte[]](0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect",[Byte[]](0x02,0x02))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect2",[Byte[]](0x10,0x02))

        return $packet_SMB2NegotiateProtocolRequest
    }

    function Get-PacketSMB2SessionSetupRequest()
    {
        param([Byte[]]$packet_security_blob)

        [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length)
        $packet_security_blob_length = $packet_security_blob_length[0,1]

        $packet_SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_StructureSize",[Byte[]](0x19,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Flags",[Byte[]](0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityMode",[Byte[]](0x01))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferOffset",[Byte[]](0x58,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferLength",$packet_security_blob_length)
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Buffer",$packet_security_blob)

        return $packet_SMB2SessionSetupRequest 
    }

    function Get-PacketSMB2TreeConnectRequest()
    {
        param([Byte[]]$packet_path)

        [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length)
        $packet_path_length = $packet_path_length[0,1]

        $packet_SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_StructureSize",[Byte[]](0x09,0x00))
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Reserved",[Byte[]](0x00,0x00))
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathOffset",[Byte[]](0x48,0x00))
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathLength",$packet_path_length)
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Buffer",$packet_path)

        return $packet_SMB2TreeConnectRequest
    }

    function Get-PacketSMB2CreateRequestFile()
    {
        param([Byte[]]$packet_named_pipe)

        $packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
        $packet_named_pipe_length = $packet_named_pipe_length[0,1]

        $packet_SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_StructureSize",[Byte[]](0x39,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Flags",[Byte[]](0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_RequestedOplockLevel",[Byte[]](0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_NameOffset",[Byte[]](0x78,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_NameLength",$packet_named_pipe_length)
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Buffer",$packet_named_pipe)

        return $packet_SMB2CreateRequestFile
    }

    function Get-PacketSMB2ReadRequest()
    {
        param ([Byte[]]$packet_file_ID)

        $packet_SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_StructureSize",[Byte[]](0x31,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Padding",[Byte[]](0x50))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Flags",[Byte[]](0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Length",[Byte[]](0x00,0x00,0x10,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_FileID",$packet_file_ID)
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoOffset",[Byte[]](0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoLength",[Byte[]](0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Buffer",[Byte[]](0x30))

        return $packet_SMB2ReadRequest
    }

    function Get-PacketSMB2WriteRequest()
    {
        param([Byte[]]$packet_file_ID,[Int]$packet_RPC_length)

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length)

        $packet_SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_StructureSize",[Byte[]](0x31,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_DataOffset",[Byte[]](0x70,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Length",$packet_write_length)
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_FileID",$packet_file_ID)
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoOffset",[Byte[]](0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoLength",[Byte[]](0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Flags",[Byte[]](0x00,0x00,0x00,0x00))

        return $packet_SMB2WriteRequest
    }

    function Get-PacketSMB2CloseRequest()
    {
        param ([Byte[]]$packet_file_ID)

        $packet_SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2CloseRequest.Add("SMB2CloseRequest_StructureSize",[Byte[]](0x18,0x00))
        $packet_SMB2CloseRequest.Add("SMB2CloseRequest_Flags",[Byte[]](0x00,0x00))
        $packet_SMB2CloseRequest.Add("SMB2CloseRequest_Reserved",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CloseRequest.Add("SMB2CloseRequest_FileID",$packet_file_ID)

        return $packet_SMB2CloseRequest
    }

    function Get-PacketSMB2TreeDisconnectRequest()
    {
        $packet_SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_StructureSize",[Byte[]](0x04,0x00))
        $packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_Reserved",[Byte[]](0x00,0x00))

        return $packet_SMB2TreeDisconnectRequest
    }

    function Get-PacketSMB2SessionLogoffRequest()
    {
        $packet_SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_StructureSize",[Byte[]](0x04,0x00))
        $packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_Reserved",[Byte[]](0x00,0x00))

        return $packet_SMB2SessionLogoffRequest
    }

    #NTLM

    function Get-PacketNTLMSSPNegotiate()
    {
        param([Byte[]]$packet_negotiate_flags,[Byte[]]$packet_version)

        [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes(32 + $packet_version.Length)
        $packet_NTLMSSP_length = $packet_NTLMSSP_length[0]
        [Byte[]]$packet_ASN_length_1 = $packet_NTLMSSP_length[0] + 32
        [Byte[]]$packet_ASN_length_2 = $packet_NTLMSSP_length[0] + 22
        [Byte[]]$packet_ASN_length_3 = $packet_NTLMSSP_length[0] + 20
        [Byte[]]$packet_ASN_length_4 = $packet_NTLMSSP_length[0] + 2

        $packet_NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialContextTokenID",[Byte[]](0x60)) # the ASN.1 key names are likely not all correct
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialcontextTokenLength",$packet_ASN_length_1)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechID",[Byte[]](0x06))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechLength",[Byte[]](0x06))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID",[Byte[]](0xa0))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength",$packet_ASN_length_2)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID2",[Byte[]](0x30))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength2",$packet_ASN_length_3)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID",[Byte[]](0xa0))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength",[Byte[]](0x0e))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID2",[Byte[]](0x30))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength2",[Byte[]](0x0c))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID3",[Byte[]](0x06))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength3",[Byte[]](0x0a))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenID",[Byte[]](0xa2))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenLength",$packet_ASN_length_4)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPID",[Byte[]](0x04))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPLength",$packet_NTLMSSP_length)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NegotiateFlags",$packet_negotiate_flags)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        if($packet_version)
        {
            $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Version",$packet_version)
        }

        return $packet_NTLMSSPNegotiate
    }

    function Get-PacketNTLMSSPAuth()
    {
        param([Byte[]]$packet_NTLM_response)

        [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLM_response.Length)
        $packet_NTLMSSP_length = $packet_NTLMSSP_length[1,0]
        [Byte[]]$packet_ASN_length_1 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 12)
        $packet_ASN_length_1 = $packet_ASN_length_1[1,0]
        [Byte[]]$packet_ASN_length_2 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 8)
        $packet_ASN_length_2 = $packet_ASN_length_2[1,0]
        [Byte[]]$packet_ASN_length_3 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 4)
        $packet_ASN_length_3 = $packet_ASN_length_3[1,0]

        $packet_NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID",[Byte[]](0xa1,0x82))
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength",$packet_ASN_length_1)
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID2",[Byte[]](0x30,0x82))
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength2",$packet_ASN_length_2)
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID3",[Byte[]](0xa2,0x82))
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength3",$packet_ASN_length_3)
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPID",[Byte[]](0x04,0x82))
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPLength",$packet_NTLMSSP_length)
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMResponse",$packet_NTLM_response)

        return $packet_NTLMSSPAuth
    }

    #RPC

    function Get-PacketRPCBind()
    {
        param([Int]$packet_call_ID,[Byte[]]$packet_max_frag,[Byte[]]$packet_num_ctx_items,[Byte[]]$packet_context_ID,[Byte[]]$packet_UUID,[Byte[]]$packet_UUID_version)

        [Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)

        $packet_RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_RPCBind.Add("RPCBind_Version",[Byte[]](0x05))
        $packet_RPCBind.Add("RPCBind_VersionMinor",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_PacketType",[Byte[]](0x0b))
        $packet_RPCBind.Add("RPCBind_PacketFlags",[Byte[]](0x03))
        $packet_RPCBind.Add("RPCBind_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_FragLength",[Byte[]](0x48,0x00))
        $packet_RPCBind.Add("RPCBind_AuthLength",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_CallID",$packet_call_ID_bytes)
        $packet_RPCBind.Add("RPCBind_MaxXmitFrag",[Byte[]](0xb8,0x10))
        $packet_RPCBind.Add("RPCBind_MaxRecvFrag",[Byte[]](0xb8,0x10))
        $packet_RPCBind.Add("RPCBind_AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_NumCtxItems",$packet_num_ctx_items)
        $packet_RPCBind.Add("RPCBind_Unknown",[Byte[]](0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_ContextID",$packet_context_ID)
        $packet_RPCBind.Add("RPCBind_NumTransItems",[Byte[]](0x01))
        $packet_RPCBind.Add("RPCBind_Unknown2",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_Interface",$packet_UUID)
        $packet_RPCBind.Add("RPCBind_InterfaceVer",$packet_UUID_version)
        $packet_RPCBind.Add("RPCBind_InterfaceVerMinor",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
        $packet_RPCBind.Add("RPCBind_TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

        if($packet_num_ctx_items[0] -eq 2)
        {
            $packet_RPCBind.Add("RPCBind_ContextID2",[Byte[]](0x01,0x00))
            $packet_RPCBind.Add("RPCBind_NumTransItems2",[Byte[]](0x01))
            $packet_RPCBind.Add("RPCBind_Unknown3",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_Interface2",[Byte[]](0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a))
            $packet_RPCBind.Add("RPCBind_InterfaceVer2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        }
        elseif($packet_num_ctx_items[0] -eq 3)
        {
            $packet_RPCBind.Add("RPCBind_ContextID2",[Byte[]](0x01,0x00))
            $packet_RPCBind.Add("RPCBind_NumTransItems2",[Byte[]](0x01))
            $packet_RPCBind.Add("RPCBind_Unknown3",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_Interface2",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
            $packet_RPCBind.Add("RPCBind_InterfaceVer2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
            $packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_ContextID3",[Byte[]](0x02,0x00))
            $packet_RPCBind.Add("RPCBind_NumTransItems3",[Byte[]](0x01))
            $packet_RPCBind.Add("RPCBind_Unknown4",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_Interface3",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
            $packet_RPCBind.Add("RPCBind_InterfaceVer3",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_InterfaceVerMinor3",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_AuthType",[Byte[]](0x0a))
            $packet_RPCBind.Add("RPCBind_AuthLevel",[Byte[]](0x04))
            $packet_RPCBind.Add("RPCBind_AuthPadLength",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_AuthReserved",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_ContextID4",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
            $packet_RPCBind.Add("RPCBind_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
            $packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
        }

        if($packet_call_ID -eq 3)
        {
            $packet_RPCBind.Add("RPCBind_AuthType",[Byte[]](0x0a))
            $packet_RPCBind.Add("RPCBind_AuthLevel",[Byte[]](0x02))
            $packet_RPCBind.Add("RPCBind_AuthPadLength",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_AuthReserved",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
            $packet_RPCBind.Add("RPCBind_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
            $packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
        }

        return $packet_RPCBind
    }

    function Get-PacketRPCRequest()
    {
        param([Byte[]]$packet_flags,[Int]$packet_service_length,[Int]$packet_auth_length,[Int]$packet_auth_padding,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_opnum,[Byte[]]$packet_data)

        if($packet_auth_length -gt 0)
        {
            $packet_full_auth_length = $packet_auth_length + $packet_auth_padding + 8
        }

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24 + $packet_full_auth_length + $packet_data.Length)
        [Byte[]]$packet_frag_length = $packet_write_length[0,1]
        [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length + $packet_data.Length)
        [Byte[]]$packet_auth_length = [System.BitConverter]::GetBytes($packet_auth_length)
        $packet_auth_length = $packet_auth_length[0,1]

        $packet_RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_RPCRequest.Add("RPCRequest_Version",[Byte[]](0x05))
        $packet_RPCRequest.Add("RPCRequest_VersionMinor",[Byte[]](0x00))
        $packet_RPCRequest.Add("RPCRequest_PacketType",[Byte[]](0x00))
        $packet_RPCRequest.Add("RPCRequest_PacketFlags",$packet_flags)
        $packet_RPCRequest.Add("RPCRequest_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_RPCRequest.Add("RPCRequest_FragLength",$packet_frag_length)
        $packet_RPCRequest.Add("RPCRequest_AuthLength",$packet_auth_length)
        $packet_RPCRequest.Add("RPCRequest_CallID",$packet_call_ID)
        $packet_RPCRequest.Add("RPCRequest_AllocHint",$packet_alloc_hint)
        $packet_RPCRequest.Add("RPCRequest_ContextID",$packet_context_ID)
        $packet_RPCRequest.Add("RPCRequest_Opnum",$packet_opnum)

        if($packet_data.Length)
        {
            $packet_RPCRequest.Add("RPCRequest_Data",$packet_data)
        }

        return $packet_RPCRequest
    }

    #SCM

    function Get-PacketSCMOpenSCManagerW()
    {
        param ([Byte[]]$packet_service,[Byte[]]$packet_service_length)

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service.Length + 92)
        [Byte[]]$packet_frag_length = $packet_write_length[0,1]
        [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service.Length + 68)
        $packet_referent_ID1 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $packet_referent_ID1 = $packet_referent_ID1.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_referent_ID1 += 0x00,0x00
        $packet_referent_ID2 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $packet_referent_ID2 = $packet_referent_ID2.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_referent_ID2 += 0x00,0x00

        $packet_SCMOpenSCManagerW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ReferentID",$packet_referent_ID1)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_MaxCount",$packet_service_length)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ActualCount",$packet_service_length)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName",$packet_service)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_ReferentID",$packet_referent_ID2)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameMaxCount",[Byte[]](0x0f,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameActualCount",[Byte[]](0x0f,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database",[Byte[]](0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Unknown",[Byte[]](0xbf,0xbf))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_AccessMask",[Byte[]](0x3f,0x00,0x00,0x00))
    
        return $packet_SCMOpenSCManagerW
    }

    function Get-PacketSCMCreateServiceW()
    {
        param([Byte[]]$packet_context_handle,[Byte[]]$packet_service,[Byte[]]$packet_service_length,
                [Byte[]]$packet_command,[Byte[]]$packet_command_length)
                
        $packet_referent_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $packet_referent_ID = $packet_referent_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_referent_ID += 0x00,0x00

        $packet_SCMCreateServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ContextHandle",$packet_context_handle)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_MaxCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_ActualCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName",$packet_service)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ReferentID",$packet_referent_ID)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_MaxCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ActualCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName",$packet_service)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_AccessMask",[Byte[]](0xff,0x01,0x0f,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceType",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceStartType",[Byte[]](0x03,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceErrorControl",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_MaxCount",$packet_command_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_ActualCount",$packet_command_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName",$packet_command)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_TagID",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer2",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DependSize",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer3",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer4",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_PasswordSize",[Byte[]](0x00,0x00,0x00,0x00))

        return $packet_SCMCreateServiceW
    }

    function Get-PacketSCMStartServiceW()
    {
        param([Byte[]]$packet_context_handle)

        $packet_SCMStartServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMStartServiceW.Add("SCMStartServiceW_ContextHandle",$packet_context_handle)
        $packet_SCMStartServiceW.Add("SCMStartServiceW_Unknown",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        return $packet_SCMStartServiceW
    }

    function Get-PacketSCMDeleteServiceW()
    {
        param([Byte[]]$packet_context_handle)

        $packet_SCMDeleteServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMDeleteServiceW.Add("SCMDeleteServiceW_ContextHandle",$packet_context_handle)

        return $packet_SCMDeleteServiceW
    }

    function Get-PacketSCMCloseServiceHandle()
    {
        param([Byte[]]$packet_context_handle)

        $packet_SCM_CloseServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCM_CloseServiceW.Add("SCMCloseServiceW_ContextHandle",$packet_context_handle)

        return $packet_SCM_CloseServiceW
    }

    $process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
    $process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
    $process_ID = $process_ID -replace "-00-00",""
    [Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

    function Get-SMBSigningStatus
    {
        param ($SMB_relay_socket,$HTTP_request_bytes,$SMB_version)

        if($SMB_relay_socket)
        {
            $SMB_relay_challenge_stream = $SMB_relay_socket.GetStream()
        }
        
        $SMB_client_receive = New-Object System.Byte[] 1024
        $SMB_client_stage = "NegotiateSMB"
        
        :SMB_relay_challenge_loop while($SMB_client_stage -ne "exit")
        {
        
            switch ($SMB_client_stage)
            {

                "NegotiateSMB"
                {
                    $packet_SMB_header = Get-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID_bytes 0x00,0x00       
                    $packet_SMB_data = Get-PacketSMBNegotiateProtocolRequest $SMB_version
                    $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                    $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                    $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                    $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                    $SMB_relay_challenge_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_relay_challenge_stream.Flush()    
                    $SMB_relay_challenge_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                    if([System.BitConverter]::ToString($SMB_client_receive[4..7]) -eq "ff-53-4d-42")
                    {
                        $SMB_version = "SMB1"
                        $SMB_client_stage = "NTLMSSPNegotiate"
                    }
                    else
                    {
                        $SMB_client_stage = "NegotiateSMB2"
                    }

                    if(($SMB_version -eq "SMB1" -and [System.BitConverter]::ToString($SMB_client_receive[39]) -eq "0f") -or ($SMB_version -ne "SMB1" -and [System.BitConverter]::ToString($SMB_client_receive[70]) -eq "03"))
                    {
                        $SMBSigningStatus = $true
                        
                    } else {
                        $SMBSigningStatus = $false
                    }
                    $SMB_relay_socket.Close()
                    $SMB_client_receive = $null
                    $SMB_client_stage = "exit"

                }
            
            }

        }
        return $SMBSigningStatus
    }

    if($Target) {
        $Targets += $Target
    }
    foreach ($Target in $Targets) {
        $SMB_relay_socket = New-Object System.Net.Sockets.TCPClient
        $SMB_relay_socket.Client.ReceiveTimeout = $Timeout
        $SMB_relay_socket.Connect($Target,"445")
        $HTTP_client_close = $false
        if(!$SMB_relay_socket.connected)
        {
        "$Target is not responding"
        }
        $SigningStatus = Get-SMBSigningStatus $SMB_relay_socket "smb2"
        if ($SigningStatus){
            "Signing Enabled"
        } else {
            "Signing Not Required"
        }
        if ($Delay) {
            $Jitter = get-random -Minimum 0 -Maximum $DelayJitter
            sleep ($Delay+$Jitter)
        }
    }

}
