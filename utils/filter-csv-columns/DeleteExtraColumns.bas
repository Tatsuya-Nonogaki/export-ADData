Sub DeleteExtraColumns()
    Dim wsData As Worksheet
    Dim wsList As Worksheet
    Dim rngList As Range
    Dim keepHeaders As Variant
    Dim lastCol As Long
    Dim i As Long
    Dim currentHeader As String
    Dim isKeep As Boolean
    Dim j As Long
    Dim headerNorm As String
    Dim keepNorm As String

    ' === Settings =========================================
    Set wsData = ActiveSheet                      ' Target worksheet (change if needed)
    Set wsList = ThisWorkbook.Worksheets("ColumnList") ' Worksheet that holds the column list
    Set rngList = wsList.Range("A1:A100")         ' Cell range that contains header names to keep
    ' ======================================================

    ' Load header names from the specified range into an array (skip empty cells)
    keepHeaders = RangeToArrayNonEmpty(rngList)
    If IsEmpty(keepHeaders) Then
        MsgBox "No valid values were found in the column list range.", vbExclamation
        Exit Sub
    End If

    Application.ScreenUpdating = False

    ' Get the last used column in row 1
    lastCol = wsData.Cells(1, wsData.Columns.Count).End(xlToLeft).Column

    ' Loop from right to left to avoid index shift issues when deleting columns
    For i = lastCol To 1 Step -1
        currentHeader = wsData.Cells(1, i).Value
        ' Normalize header: trim leading/trailing spaces and ignore case
        headerNorm = UCase$(Trim$(CStr(currentHeader)))
        isKeep = False

        ' Check if the current header exists in the keep list
        For j = LBound(keepHeaders) To UBound(keepHeaders)
            keepNorm = UCase$(Trim$(CStr(keepHeaders(j))))
            If headerNorm = keepNorm Then
                isKeep = True
                Exit For
            End If
        Next j

        ' Delete the whole column if the header is not in the keep list
        If Not isKeep Then
            wsData.Columns(i).Delete
        End If
    Next i

    Application.ScreenUpdating = True
    MsgBox "Column cleanup completed.", vbInformation
End Sub

' Helper: convert a range to a 1D array, skipping empty cells
Private Function RangeToArrayNonEmpty(rng As Range) As Variant
    Dim c As Range
    Dim tmp As Collection
    Dim arr() As Variant
    Dim i As Long

    Set tmp = New Collection

    For Each c In rng.Cells
        If Len(Trim$(CStr(c.Value))) > 0 Then
            tmp.Add c.Value
        End If
    Next c

    If tmp.Count = 0 Then
        RangeToArrayNonEmpty = Empty
        Exit Function
    End If

    ReDim arr(0 To tmp.Count - 1)
    For i = 1 To tmp.Count
        arr(i - 1) = tmp(i)
    Next i

    RangeToArrayNonEmpty = arr
End Function
