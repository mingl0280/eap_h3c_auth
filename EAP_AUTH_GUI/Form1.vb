﻿Imports System.IO
Imports System.Threading
Imports System.Diagnostics.Process
Imports System.Diagnostics
Imports System.Net.Configuration
Imports System.Net
Imports System.Net.NetworkInformation
Imports System.Management

Public Class Form1
    Private Structure NetDevices
        Public DeviceName As String
        Public DevicePCAPStr As String
    End Structure

    Dim nDeviceList() As NetDevices

    Private Sub Form1_Load(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles MyBase.Load
        '文件读写初始化
        If Not File.Exists("Config.ini") Then
            File.Create(Application.StartupPath + "\Config.ini")
        End If
        Button1.Enabled = False
        Button2.Enabled = False
        '网卡列表初始化
        Dim count As Integer = 0
        'TextBox3.Visible = False
        Dim Wmi As New System.Management.ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration where(IPEnabled = true)")
        For Each WmiObj As ManagementObject In Wmi.Get
            ReDim Preserve nDeviceList(count + 1)
            nDeviceList(count).DeviceName = WmiObj("Description")
            ComboBox1.Items.Add(WmiObj("Description"))
            'TextBox3.Text = TextBox3.Text + WmiObj("InterfaceIndex").ToString + " " + WmiObj("Description").ToString _
            '+ " " + WmiObj("SettingID").ToString + " " + WmiObj("IPEnabled").ToString + vbCrLf
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

    Private Sub Button1_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button1.Click
        sArg = "/connect" + " " + TextBox1.Text + " " _
        + TextBox2.Text + " " + nDeviceList(ComboBox1.SelectedIndex).DevicePCAPStr
        'Thread.Sleep(1000)
        'Form2.Show()
        '保存上次的信息
        SaveUserInfo(TextBox1.Text, TextBox2.Text, ComboBox1.SelectedItem, CheckBox1.Checked, CheckBox2.Checked)
        BeginAuth()
    End Sub

    Private Sub TextBox1_TextChanged(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles TextBox1.TextChanged
        If TextBox1.Text <> "" and textbox2.Text <> "" and combobox1.SelectedItem <> "" Then
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

    Private Sub Button2_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button2.Click
        sArg = "/disconnect " + nDeviceList(ComboBox1.SelectedIndex).DevicePCAPStr
        SaveUserInfo(TextBox1.Text, TextBox2.Text, ComboBox1.Text, CheckBox1.Checked, CheckBox2.Checked)
        BeginAuth()
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
End Class
