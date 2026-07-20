"""Exports the results table to an .xlsx file."""


def export_to_excel(path: str, rows: list[list[str]], headers: list[str]) -> None:
    from openpyxl import Workbook

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "DHCP Lease Inspector"
    sheet.append(headers)
    for row in rows:
        sheet.append(row)

    for column_cells in sheet.columns:
        width = max(len(str(cell.value)) for cell in column_cells if cell.value is not None)
        sheet.column_dimensions[column_cells[0].column_letter].width = max(width + 2, 10)

    workbook.save(path)
