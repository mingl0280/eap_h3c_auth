Public Class FrmAuth
    Private Delegate Sub opDeleg(ByRef s As String)

    Private Sub FrmAuth_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        With TextBox1
            .Multiline = True
            .Dock = DockStyle.Fill
            .BackColor = Color.Black
            .ForeColor = Color.Lime
        End With
    End Sub

    Public Function onDataRecv(ByVal sender As Object, ByVal e As DataReceivedEventArgs)
        Me.Invoke(New opDeleg(AddressOf changeText), e.Data)
        Return Nothing
    End Function

    Private Sub changeText(ByRef s As String)
        TextBox1.Text += s + vbCrLf
    End Sub
End Class