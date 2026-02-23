' DeleteExtraColumns.bas
'
' This macro creates a new worksheet that contains only the columns
' whose headers are listed in a configurable "ColumnList" range.
' The original worksheet is not modified, but a new worksheet is added to the workbook.
' It is recommended to work on a copy of your workbook or keep a backup
' before applying this macro.
'
' Usage:
'   1) Prepare a list of column headers to keep (one header per cell).
'      - Recommended: on the worksheet named "ColumnList", create a named range "ColumnList"
'        that covers your header list (workbook- or sheet-scoped; any size such as A1:A20, A1:A300, etc.).
'      - Alternative: you may also define a named range "ColumnList" on any worksheet;
'        in that case, it must be workbook-scoped.
'      - Fallback: if no named range is found, the macro uses the fixed range "ColumnList"!A1:A100.
'   2) Activate the source worksheet that contains the data to be filtered.
'   3) Run DeleteExtraColumns. A new worksheet (e.g. "Sheet1_Filtered") will be created,
'      and columns not listed in the column list will be removed from that new sheet.
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
    Set wsList = ThisWorkbook.Worksheets("ColumnList")   ' Worksheet that holds the column list (fallback)
    ' Resolve the column list range (workbook- or worksheet-scoped named range, or the fixed range).
    ' Function arguments: workbook, default worksheet, range name, default cell range.
    Set rngList = ResolveColumnListRange(ThisWorkbook, wsList, "ColumnList", "A1:A100")
    ' ======================================================

    keepHeaders = RangeToArrayNonEmpty(rngList)
    If IsEmpty(keepHeaders) Then
        MsgBox "No valid values were found in the column list range.", vbExclamation
        Exit Sub
    End If

    Application.ScreenUpdating = False

    ' Work on a copied worksheet so the original remains intact
    On Error Resume Next
    wsSource.Copy After:=wsSource
    If Err.Number <> 0 Then
        Dim copyErrMsg As String
        copyErrMsg = "Failed to copy the source worksheet." & vbCrLf & _
                     "Please check if sheet copying is allowed for this workbook." & vbCrLf & _
                     "Error " & Err.Number & ": " & Err.Description
        MsgBox copyErrMsg, vbExclamation

        Err.Clear
        Application.ScreenUpdating = True
        On Error GoTo 0
        Exit Sub
    End If
    On Error GoTo 0

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

' Resolve the column list range using a named range if available.
' Priority:
'   1) Workbook-scoped named range (ThisWorkbook.Names)
'   2) Worksheet-scoped named range (wsFallback.Names)
'   3) Fallback to wsFallback.Range(fallbackAddress)
Private Function ResolveColumnListRange(wb As Workbook, wsFallback As Worksheet, _
                                       ByVal namedRange As String, ByVal fallbackAddress As String) As Range
    Dim nm As Name

    ' 1) Workbook-scoped name
    On Error Resume Next
    Set nm = wb.Names(namedRange)
    On Error GoTo 0
    If Not nm Is Nothing Then
        Set ResolveColumnListRange = nm.RefersToRange
        Exit Function
    End If

    ' 2) Worksheet-scoped name (e.g. ColumnList sheet local name)
    On Error Resume Next
    Set nm = wsFallback.Names(namedRange)
    On Error GoTo 0
    If Not nm Is Nothing Then
        Set ResolveColumnListRange = nm.RefersToRange
        Exit Function
    End If

    ' 3) Fallback address
    Set ResolveColumnListRange = wsFallback.Range(fallbackAddress)
End Function

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
