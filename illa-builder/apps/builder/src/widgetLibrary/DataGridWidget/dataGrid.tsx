import { StyledEngineProvider, ThemeProvider, createTheme } from "@mui/material"
import {
  DataGrid,
  type GridColDef,
  type GridColumnVisibilityModel,
  type GridEventListener,
  type GridFilterModel,
  type GridPaginationModel,
  type GridRowIdGetter,
  type GridRowParams,
  type GridRowSelectionModel,
  type GridSortModel,
} from "@mui/x-data-grid"
import type { GridApi } from "@mui/x-data-grid"
import { get, isArray, isNumber, isPlainObject } from "lodash-es"
import {
  FC,
  MutableRefObject,
  useCallback,
  useEffect,
  useMemo,
  useRef,
} from "react"
import { useDispatch } from "react-redux"
import { getColor } from "@illa-design/react"
import { dealRawData2ArrayData } from "@/page/App/components/InspectPanel/PanelSetters/DataGridSetter/utils"
import { configActions } from "@/redux/config/configSlice"
import {
  getColumnFromType,
  getColumnTypeFromValue,
  getSafeColumn,
} from "@/widgetLibrary/DataGridWidget/columnDeal"
import { Toolbar } from "./Toolbar"
import { UNIQUE_ID_NAME } from "./constants"
import { BaseDataGridProps } from "./interface"
import { getDataGridLocalization } from "./utils"

export const DataGridWidget: FC<BaseDataGridProps> = (props) => {
  const {
    loading,
    triggerEventHandler,
    dataSource,
    dataSourceJS,
    dataSourceMode,
    sortKey,
    sortOrder,
    handleUpdateMultiExecutionResult,
    displayName,
    rowSelection,
    rowSelectionMode,
    pageSize,
    page,
    pageSizeOptions,
    columnSetting,
    densitySetting,
    refreshSetting,
    quickFilterSetting,
    exportSetting,
    exportAllSetting,
    filterSetting,
    enableServerSidePagination,
    totalRowCount,
    primaryKey,
    filterModel,
    selectedRowsPrimaryKeys,
    excludeHiddenColumns,
    columnVisibilityModel,
    updateComponentRuntimeProps,
    deleteComponentRuntimeProps,
    columns,
    enablePagination,
  } = props

  const rawData = dataSourceMode === "dynamic" ? dataSourceJS : dataSource
  const serverSideOffset = (page ?? 0) * (pageSize ?? 10)

  const arrayData: object[] = useMemo(
    () =>
      dealRawData2ArrayData(
        rawData,
        enableServerSidePagination,
        serverSideOffset,
      ),
    [rawData, enableServerSidePagination, serverSideOffset],
  )

  const ref = useRef<GridApi>(null) as MutableRefObject<GridApi>

  const dispatch = useDispatch()

  const isInnerDragging = useRef(false)

  const toolbar = useCallback(
    () => (
      <Toolbar
        columnSetting={columnSetting}
        densitySetting={densitySetting}
        exportSetting={exportSetting}
        exportAllSetting={exportAllSetting}
        filterSetting={filterSetting}
        quickFilterSetting={quickFilterSetting}
        refreshSetting={refreshSetting}
        onRefresh={() => {
          triggerEventHandler("onRefresh")
        }}
      />
    ),
    [
      columnSetting,
      densitySetting,
      exportAllSetting,
      exportSetting,
      filterSetting,
      quickFilterSetting,
      refreshSetting,
      triggerEventHandler,
    ],
  )

  useEffect(() => {
    updateComponentRuntimeProps({
      refresh: () => {
        triggerEventHandler("onRefresh")
      },
      setFilterModel: (model: unknown) => {
        if (
          isPlainObject(model) &&
          (model as Record<string, unknown>).hasOwnProperty("items") &&
          Array.isArray((model as Record<string, unknown>).items)
        ) {
          handleUpdateMultiExecutionResult([
            {
              displayName,
              value: {
                filterModel: model,
              },
            },
          ])
          triggerEventHandler("onFilterModelChange")
        }
      },
      setColumnVisibilityModel: (model: unknown) => {
        if (isPlainObject(model)) {
          handleUpdateMultiExecutionResult([
            {
              displayName,
              value: {
                columnVisibilityModel: model,
              },
            },
          ])
          triggerEventHandler("onColumnVisibilityModelChange")
        }
      },
      setPage: (page: unknown) => {
        if (isNumber(page)) {
          handleUpdateMultiExecutionResult([
            {
              displayName,
              value: {
                page,
              },
            },
          ])
          triggerEventHandler("onPaginationModelChange")
        }
      },
      setPageSize: (pageSize: unknown) => {
        if (isNumber(pageSize)) {
          handleUpdateMultiExecutionResult([
            {
              displayName,
              value: {
                pageSize,
              },
            },
          ])
          triggerEventHandler("onPaginationModelChange")
        }
      },
      setRowSelection: (rows: unknown) => {
        if (isArray(rows) && rows.every((row) => !isNaN(row))) {
          handleUpdateMultiExecutionResult([
            {
              displayName,
              value: {
                selectedRowsPrimaryKeys: rows,
                selectedRows: rows.map((id) => ref.current.getRow(id)),
              },
            },
          ])
          triggerEventHandler("onRowSelectionModelChange")
        }
      },
    })
    return () => {
      deleteComponentRuntimeProps()
    }
  }, [
    updateComponentRuntimeProps,
    deleteComponentRuntimeProps,
    triggerEventHandler,
    handleUpdateMultiExecutionResult,
    displayName,
  ])

  const renderColumns = useMemo(() => {
    if (!columns) return []
    return columns.map((column) => {
      const safeColumn = getSafeColumn(column)
      return safeColumn.columnType === "auto"
        ? getColumnFromType(
            {
              ...safeColumn,
              columnType: getColumnTypeFromValue(
                get(arrayData[0], safeColumn.field),
              ),
            },
            triggerEventHandler,
          )
        : getColumnFromType(safeColumn, triggerEventHandler)
    })
  }, [arrayData, columns, triggerEventHandler])

  const innerFilterModel =
    filterModel !== undefined
      ? {
          ...filterModel,
          quickFilterExcludeHiddenColumns:
            filterModel.quickFilterExcludeHiddenColumns ?? excludeHiddenColumns,
        }
      : undefined

  const sortModel =
    sortKey != undefined && sortOrder != undefined
      ? [
          {
            field: sortKey,
            sort: sortOrder === "default" ? null : sortOrder,
          },
        ]
      : []

  const innerRowSelection =
    rowSelection &&
    (rowSelectionMode === "multiple" || rowSelectionMode === "single")

  const paginationModel =
    pageSize !== undefined
      ? {
          pageSize: pageSize ?? 10,
          page: page ?? 0,
        }
      : {
          pageSize: 100,
          page: 0,
        }
  const paginationMode = enablePagination
    ? enableServerSidePagination
      ? "server"
      : "client"
    : undefined

  const getRowID: GridRowIdGetter = (row: Record<string, unknown>) => {
    if (
      primaryKey === undefined ||
      primaryKey === "—" ||
      !(primaryKey in row)
    ) {
      return get(row, UNIQUE_ID_NAME) as string | number
    } else {
      return get(row, primaryKey) as string | number
    }
  }

  const onRowClick: GridEventListener<"rowClick"> = (params: GridRowParams) => {
    handleUpdateMultiExecutionResult([
      {
        displayName,
        value: {
          clickedRow: params.row,
        },
      },
    ])
    triggerEventHandler("onRowClick")
  }

  const onFilterModelChange = (model: GridFilterModel) => {
    handleUpdateMultiExecutionResult([
      {
        displayName,
        value: {
          filterModel: model,
        },
      },
    ])
    triggerEventHandler("onFilterModelChange")
  }

  const onColumnVisibilityModelChange = (model: GridColumnVisibilityModel) => {
    handleUpdateMultiExecutionResult([
      {
        displayName,
        value: {
          columnVisibilityModel: model,
        },
      },
    ])
    triggerEventHandler("onColumnVisibilityModelChange")
  }

  const onRowSelectionModelChange = (model: GridRowSelectionModel) => {
    handleUpdateMultiExecutionResult([
      {
        displayName,
        value: {
          selectedRowsPrimaryKeys: model,
          selectedRows: model.map((id: string | number) =>
            ref.current.getRow(id),
          ),
        },
      },
    ])
    triggerEventHandler("onRowSelectionModelChange")
  }

  const onPaginationModelChange = (model: GridPaginationModel) => {
    handleUpdateMultiExecutionResult([
      {
        displayName,
        value: {
          page: model.page,
          pageSize: model.pageSize,
        },
      },
    ])
    triggerEventHandler("onPaginationModelChange")
  }

  const onSortModelChange = (model: GridSortModel) => {
    if (model.length > 0) {
      handleUpdateMultiExecutionResult([
        {
          displayName,
          value: {
            sortKey: model[0].field,
            sortOrder: model[0].sort,
          },
        },
      ])
    } else {
      handleUpdateMultiExecutionResult([
        {
          displayName,
          value: {
            sortKey: undefined,
            sortOrder: undefined,
          },
        },
      ])
    }
    triggerEventHandler("onSortModelChange")
  }

  const onColumnHeaderEnter = () => {
    dispatch(
      configActions.setResizingNodeIDsReducer([
        `${displayName}-column-header-resize`,
      ]),
    )
    isInnerDragging.current = true
  }

  const onColumnHeaderLeave = () => {
    dispatch(configActions.setResizingNodeIDsReducer([]))
    isInnerDragging.current = false
  }

  return (
    <StyledEngineProvider injectFirst>
      <ThemeProvider
        theme={createTheme({
          palette: {
            primary: { main: getColor("blue", "03") },
          },
        })}
      >
        <DataGrid
          localeText={getDataGridLocalization()}
          key={displayName + ":" + primaryKey}
          getRowId={getRowID}
          filterModel={innerFilterModel}
          rowSelectionModel={
            innerRowSelection ? selectedRowsPrimaryKeys : undefined
          }
          rowSelection={innerRowSelection}
          columnVisibilityModel={{
            [UNIQUE_ID_NAME]: false,
            ...columnVisibilityModel,
          }}
          sortModel={sortModel}
          // pagination={undefined}
          pageSizeOptions={isArray(pageSizeOptions) ? pageSizeOptions : []}
          autoPageSize={pageSize === undefined}
          checkboxSelection={
            innerRowSelection && rowSelectionMode === "multiple"
          }
          rows={arrayData}
          columns={(renderColumns as GridColDef[]) ?? []}
          rowCount={
            enablePagination && enableServerSidePagination && totalRowCount
              ? totalRowCount
              : arrayData.length
          }
          keepNonExistentRowsSelected={enableServerSidePagination}
          loading={loading}
          slots={{
            toolbar: toolbar,
          }}
          paginationModel={paginationModel}
          paginationMode={paginationMode}
          onFilterModelChange={onFilterModelChange}
          onColumnVisibilityModelChange={onColumnVisibilityModelChange}
          onRowSelectionModelChange={onRowSelectionModelChange}
          onRowClick={onRowClick}
          onPaginationModelChange={onPaginationModelChange}
          onSortModelChange={onSortModelChange}
          onColumnHeaderEnter={onColumnHeaderEnter}
          onColumnHeaderLeave={onColumnHeaderLeave}
        />
      </ThemeProvider>
    </StyledEngineProvider>
  )
}

DataGridWidget.displayName = "DataGridWidget"
export default DataGridWidget
