import SaveAltIcon from "@mui/icons-material/SaveAlt"
import { Button, Menu, MenuItem } from "@mui/material"
import type {
  GridCsvGetRowsToExportParams,
} from "@mui/x-data-grid"
import {
  gridSortedRowIdsSelector,
  useGridApiContext,
} from "@mui/x-data-grid"
import { GridApiCommunity } from "@mui/x-data-grid/models/api/gridApiCommunity"
import { FC, useState } from "react"
import { useTranslation } from "react-i18next"

export const ExportAllSetting: FC = () => {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null)

  const apiRef = useGridApiContext()

  const open = Boolean(anchorEl)
  const handleClose = () => {
    setAnchorEl(null)
  }

  const { t } = useTranslation()

  return (
    <>
      <Button
        startIcon={<SaveAltIcon />}
        size="small"
        id="basic-button"
        aria-controls={open ? "basic-menu" : undefined}
        aria-haspopup="true"
        aria-expanded={open ? "true" : undefined}
        onClick={(event) => {
          setAnchorEl(event.currentTarget)
        }}
      >
        {t("widget.table.export_all_data")}
      </Button>
      <Menu
        id="basic-menu"
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        MenuListProps={{
          "aria-labelledby": "basic-button",
        }}
      >
        <MenuItem
          onClick={() => {
            apiRef.current.exportDataAsCsv({
              getRowsToExport: (params: GridCsvGetRowsToExportParams<GridApiCommunity>) =>
                gridSortedRowIdsSelector(params.apiRef),
            })
          }}
        >
          {t("widget.table.export.csv")}
        </MenuItem>
      </Menu>
    </>
  )
}

ExportAllSetting.displayName = "ExportAllSetting"
