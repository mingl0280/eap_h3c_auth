﻿Imports System.IO
Imports System.Text.Encoding

Module ModuleFunctions
#Region "Declare APIs"
    '两个读写ini文件的函数
    Private Declare Function GetPrivateProfileString Lib "kernel32" Alias "GetPrivateProfileStringA" _
    (ByVal lpApplicationName As String, ByVal lpKeyName As String, ByVal lpDefault As String, ByVal lpReturnedString As String, _
     ByVal nSize As Int32, ByVal lpFileName As String) _
     As Int32
    Private Declare Function WritePrivateProfileString Lib "kernel32" Alias "WritePrivateProfileStringA" (ByVal lpApplicationName As String, ByVal lpKeyName As String, ByVal lpString As String, ByVal lpFileName As String) As Boolean
    Public PingSent, PingRecv As Integer
#End Region
    '启动认证字串
    Public Delegate Function vDelegate(ByRef s As String)
    Public sArg As String = ""
    '此函数获取控制台输出有误，暂不接入管道。
    Public Sub BeginAuth()
        Dim AuthProcess As Process = New Process()
        Dim sConsoleRead As String = ""
        AuthProcess.StartInfo.FileName = "EAP_H3C_AUTH.exe"
        'AuthProcess.StartInfo.UseShellExecute = False
        'AuthProcess.StartInfo.CreateNoWindow = True
        'AuthProcess.StartInfo.RedirectStandardInput = True
        'AuthProcess.StartInfo.RedirectStandardOutput = True
        'AuthProcess.StartInfo.RedirectStandardError = True
        AuthProcess.StartInfo.Arguments = sArg

        AuthProcess.Start()

        'Dim AInput As StreamWriter = AuthProcess.StandardInput
        'Dim AOutput As StreamReader = AuthProcess.StandardOutput
        'Dim AErr As StreamReader = AuthProcess.StandardError


        'While AuthProcess.HasExited = False
        'sConsoleRead = AOutput.ReadLine + vbCrLf
        'Form2.Invoke(New vDelegate(AddressOf SendInfo), sConsoleRead)
        'End While

        'While 1
        ' sConsoleRead = AOutput.ReadLine()
        'While Form2.IsDisposed <> False
        'Form2.Invoke(New vDelegate(AddressOf SendInfo), sConsoleRead)
        'Thread.Sleep(1000)
        'End While
        'End While
    End Sub
    '窗体2更新函数
    Private Function SendInfo(ByRef s As String)
        Form2.TextBox1.Text += s + vbCrLf
    End Function
    'ini读取函数
    Public Function readini(ByVal key As String, ByRef dststr As String) As String
        Dim isex As Integer
        isex = IO.File.Exists("Config.ini")
        If Not isex Then
            IO.File.Create(Application.StartupPath + "\Config.ini")

            Return ""
        Else
            Dim str As String
            str = ""
            str = LSet(str, 512)
            Dim currentdir As String = Application.StartupPath + "\Config.ini"
            GetPrivateProfileString("main", key, "", str, Len(str), currentdir)
            dststr = Left(str, InStr(str, Chr(0)) - 1)
            Return 1
        End If
    End Function
    '写入ini函数
    Public Function writeini(ByVal key As String, ByVal str As String) As Boolean
        Dim isex As Integer
        isex = File.Exists("Config.ini")
        If Not isex Then
            File.Create(Application.StartupPath + "\Config.ini")
            'MsgBox("无法打开LaunchSET.ini,请确定本程序已经放置于EVE Online根目录下!!!")
            'Return 0
        End If
        Dim path As String
        path = Application.StartupPath + "\Config.ini"
        WritePrivateProfileString("main", key, str, path)
    End Function

    '获取已经保存的用户名和密码
    Public Function GetSavedUserInfo(ByRef User As String, ByRef password As String, ByRef DevName As String)
        Dim duser As String = ""
        Dim dpass As String = ""
        Dim dname As String = ""
        Dim sShowPass, sRemPass As String
        sShowPass = ""
        sRemPass = ""

        readini("ShowPass", sShowPass)
        readini("RemPass", sRemPass)

        readini("Username", duser)      '用户名
        readini("DeviceName", dname)    '设备名

        User = duser
        DevName = dname
        '如果记住密码
        If sRemPass = "True" Or sRemPass = "" Then
            readini("Password", dpass)
            password = Base64Decode(dpass)
            Form1.CheckBox1.Checked = True
        Else
            password = ""
        End If
        '如果显示密码
        If sShowPass = "True" Or sShowPass = "" Then
            Form1.TextBox2.UseSystemPasswordChar = False
            Form1.CheckBox2.Checked = True
        End If
    End Function
    '写入保存的用户名与密码
    Public Function SaveUserInfo(ByVal User As String, ByVal pass As String, ByVal DevName As String,ByVal RemPass As Boolean,ByVal ShowPass as Boolean)
        Dim SecurePass As String = Base64Encode(pass)
        writeini("Username", User)
        '记住密码
        If RemPass = True Then
            writeini("Password", SecurePass)
            writeini("RemPass", "True")
        Else
            writeini("Password", "")
            writeini("RemPass", "False")
        End If
        writeini("DeviceName", DevName)
        '显示密码
        If ShowPass = True Then
            writeini("ShowPass", "True")
        Else
            writeini("ShowPass", "False")
        End If
    End Function
    'Base64加密与解密函数
    Public Function Base64Encode(ByVal s_src As String) As String
        Dim bbyte() As Byte
        bbyte = ASCII.GetBytes(s_src)
        Dim s_enc As String = System.Convert.ToBase64String(bbyte)
        Return s_enc
    End Function
    Public Function Base64Decode(ByVal s_enc As String) As String
        Dim bbyte() As Byte
        bbyte = System.Convert.FromBase64String(s_enc)
        Dim s_src As String = ASCII.GetString(bbyte)
        Return s_src
    End Function

End Module
