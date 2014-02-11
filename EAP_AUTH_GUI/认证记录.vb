Imports System.IO
Imports System.Threading
Imports System.Diagnostics.Process
Imports System.Diagnostics
Imports System.Net.Configuration
Imports System.Net
Imports System.Net.NetworkInformation
Imports System.Management

Public Class Form2

    Private Sub Form2_Load(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles MyBase.Load
        Dim pthread As Thread = New Thread(AddressOf BeginAuth)
        pthread.Start()
    End Sub
End Class