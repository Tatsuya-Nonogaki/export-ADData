' DeleteExtraColumns.bas
'
' This macro creates a new worksheet that contains only the columns
' whose headers are listed in the "ColumnList" sheet. The original
' worksheet is not modified, but a new worksheet is added to the workbook.
' It is recommended to work on a copy of your workbook or keep a backup
' before applying this macro.
'
' Usage:
'   - Put the list of column headers to keep in the "ColumnList" sheet (range A1:A100 by default).
'   - Activate the source worksheet that contains the data to be filtered.
'   - Run DeleteExtraColumns. A new worksheet (e.g. "Sheet1_Filtered") will be created,
'     and columns not listed in "ColumnList" will be removed from that new sheet.
'
Sub DeleteExtraColumns()
    Dim wsSource As Worksheet
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
    Dim newName As String

    ' === Settings =========================================
    Set wsSource = ActiveSheet                           ' Source worksheet (will NOT be modified)
    Set wsList = ThisWorkbook.Worksheets("ColumnList")   ' Worksheet that holds the column list
    Set rngList = wsList.Range("A1:A100")                ' Cell range that contains header names to keep
    ' ======================================================

    ' Load header names from the specified range into an array (skip empty cells)
    keepHeaders = RangeToArrayNonEmpty(rngList)
    If IsEmpty(keepHeaders) Then
        MsgBox "No valid values were found in the column list range.", vbExclamation
        Exit Sub
    End If

    Application.ScreenUpdating = False

    ' Work on a copied worksheet so the original remains intact
    wsSource.Copy After:=wsSource
    Set wsData = wsSource.Next

    ' Try to give the copied sheet a descriptive name
    newName = wsSource.Name & "_Filtered"
    On Error Resume Next
    wsData.Name = newName
    On Error GoTo 0

    ' Get the last used column in row 1 on the copied sheet
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
    MsgBox "Column cleanup completed on the copied worksheet.", vbInformation
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
