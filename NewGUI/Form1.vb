Imports System.IO
Imports System.Management

Public Class Form1
    Private Structure NetDevices
        Public DeviceName As String
        Public DevicePCAPStr As String
    End Structure

    Private nDeviceList() As NetDevices

    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        If Not File.Exists("Config.ini") Then
            File.Create(Application.StartupPath + "\Config.ini").Close()
        End If
        Button1.Enabled = False
        Button2.Enabled = False
        '网卡列表初始化
        Dim count As Integer = 0
        Dim Wmi As New System.Management.ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration where(IPEnabled = true)")
        For Each WmiObj As ManagementObject In Wmi.Get
            ReDim Preserve nDeviceList(count + 1)
            nDeviceList(count).DeviceName = WmiObj("Description")
            ComboBox1.Items.Add(WmiObj("Description"))
            nDeviceList(count).DevicePCAPStr = "rpcap://\DEVICE\NPF_" + WmiObj("SettingID")
            count = count + 1
        Next
        '读取保存的用户名与密码（如果存在）
        Dim usr As String = ""
        Dim psw As String = ""
        Dim NDevice As String = ""
        GetSavedUserInfo(usr, psw, NDevice)
        TextBox1.Text = usr
        TextBox2.Text = psw
        ComboBox1.SelectedItem = NDevice
    End Sub

    Private Sub TextBox1_TextChanged(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles TextBox1.TextChanged
        If TextBox1.Text <> "" And TextBox2.Text <> "" And ComboBox1.SelectedItem <> "" Then
            Button1.Enabled = True
        Else
            Button1.Enabled = False
        End If
        If ComboBox1.SelectedItem <> "" Then
            Button2.Enabled = True
        Else
            Button2.Enabled = False
        End If
    End Sub

    Private Sub TextBox2_TextChanged(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles TextBox2.TextChanged
        If TextBox1.Text <> "" And TextBox2.Text <> "" And ComboBox1.SelectedItem <> "" Then
            Button1.Enabled = True
        Else
            Button1.Enabled = False
        End If
        If ComboBox1.SelectedItem <> "" Then
            Button2.Enabled = True
        Else
            Button2.Enabled = False
        End If
    End Sub

    Private Sub ComboBox1_SelectedIndexChanged(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles ComboBox1.SelectedIndexChanged
        If TextBox1.Text <> "" And TextBox2.Text <> "" And ComboBox1.SelectedItem <> "" Then
            Button1.Enabled = True
        Else
            Button1.Enabled = False
        End If
        If ComboBox1.SelectedItem <> "" Then
            Button2.Enabled = True
        Else
            Button2.Enabled = False
        End If

    End Sub
    Private Sub ComboBox1_TextChanged(ByVal sender As Object, ByVal e As System.EventArgs) Handles ComboBox1.TextChanged
        If TextBox1.Text <> "" And TextBox2.Text <> "" And ComboBox1.SelectedItem <> "" Then
            Button1.Enabled = True
        Else
            Button1.Enabled = False
        End If
        If ComboBox1.SelectedItem <> "" Then
            Button2.Enabled = True
        Else
            Button2.Enabled = False
        End If
    End Sub
    Private Sub CheckBox2_CheckedChanged(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles CheckBox2.CheckedChanged
        If CheckBox2.Checked Then
            TextBox2.UseSystemPasswordChar = False
        Else
            TextBox2.UseSystemPasswordChar = True
        End If
    End Sub
    Private Sub Button3_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button3.Click
        SaveUserInfo("", "", "", False, False)
        TextBox1.Text = ""
        TextBox2.Text = ""
        ComboBox1.Text = ""
        CheckBox1.Checked = False
        CheckBox2.Checked = False
    End Sub

    Private Sub Button1_Click(sender As Object, e As EventArgs) Handles Button1.Click
        Dim sArg As String = ""
        sArg = "/connect" + " " + TextBox1.Text + " " + TextBox2.Text + " " + nDeviceList(ComboBox1.SelectedIndex).DevicePCAPStr
        SaveUserInfo(TextBox1.Text, TextBox2.Text, ComboBox1.SelectedItem, CheckBox1.Checked, CheckBox2.Checked)
        FrmAuth.Show()
        BeginAuth(sArg)
    End Sub

    Private Sub BeginAuth(ByVal Arg As String)
        Dim dProcess As New Process()
        With dProcess.StartInfo
            .FileName = "EAP_H3C_AUTH.exe"
            .Arguments = Arg
            .UseShellExecute = False
            .RedirectStandardOutput = True
            .RedirectStandardError = True
            .CreateNoWindow = True
            .WindowStyle = ProcessWindowStyle.Hidden
        End With
        AddHandler dProcess.OutputDataReceived, AddressOf FrmAuth.onDataRecv
        AddHandler dProcess.ErrorDataReceived, AddressOf FrmAuth.onDataRecv
        AddHandler dProcess.OutputDataReceived, AddressOf debugout
        AddHandler dProcess.ErrorDataReceived, AddressOf debugout
        dProcess.Start()

        dProcess.BeginErrorReadLine()
        dProcess.BeginOutputReadLine()
    End Sub
    Private Function debugout(sender As Object, e As DataReceivedEventArgs)
        Debug.WriteLine(e.Data)
    End Function

End Class
