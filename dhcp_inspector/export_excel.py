"""Exports the results table to an .xlsx file."""

_STATUS_FILLS = {
    "Ready": "C8E6C9",          # green
    "Domain Issue": "FFF9C4",   # yellow
    "Patch Overdue": "FFF9C4",
    "Offline": "FFCDD2",        # red
    "Error": "FFCDD2",
    "No DNS": "FFCDD2",
}


def export_to_excel(path: str, rows: list[list[str]], headers: list[str]) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "DHCP Lease Inspector"

    sheet.append(headers)
    for cell in sheet[1]:
        cell.font = Font(bold=True)

    status_col = headers.index("Status") if "Status" in headers else None
    for row in rows:
        sheet.append(row)
        if status_col is not None:
            fill_hex = _STATUS_FILLS.get(row[status_col])
            if fill_hex:
                fill = PatternFill(start_color=fill_hex, end_color=fill_hex, fill_type="solid")
                for cell in sheet[sheet.max_row]:
                    cell.fill = fill

    for column_cells in sheet.columns:
        width = max(len(str(cell.value)) for cell in column_cells if cell.value is not None)
        sheet.column_dimensions[column_cells[0].column_letter].width = max(width + 2, 10)

    workbook.save(path)
