# KQL Cheat Sheet for Microsoft Defender & Sentinel

A quick reference for Kusto Query Language (KQL) syntax, operators, and common patterns used in Microsoft Defender, Sentinel, and Azure Data Explorer.

---

## Basic Query Structure
```kql
TableName
| where <condition>
| project <columns>
| summarize <aggregation>
| order by <column> desc
```

## Filtering
```kql
| where Column == "value"
| where Column != "value"
| where Column has "substring"
| where Column contains "substring"
| where Column startswith "prefix"
| where Column endswith "suffix"
| where Column in ("A", "B", "C")
| where Column matches regex "pattern"
```

## Projection
```kql
| project Column1, Column2, NewName = Column3
| project-away UnwantedColumn
```

## Aggregation
```kql
| summarize Count = count() by Column
| summarize Total = sum(Column) by AnotherColumn
| summarize Avg = avg(Column)
| summarize Events = make_list(Column, 10)
```

## Time Filtering
```kql
| where Timestamp > ago(1d)
| where Timestamp between (datetime(2024-01-01) .. datetime(2024-01-31))
```

## Sorting
```kql
| sort by Column desc
| order by Column asc
```

## Joins
```kql
TableA
| join kind=inner (TableB) on KeyColumn
| join kind=leftouter (TableB) on KeyColumn
```

## Unions
```kql
TableA
| union TableB
```

## Parsing
```kql
| parse Column with "prefix" value "," rest
| parse kind=regex Column with @"(?<Field1>\w+)-(?<Field2>\d+)"
```

## String Operations
```kql
| extend Lower = tolower(Column)
| extend Upper = toupper(Column)
| extend Trimmed = trim(" ", Column)
| extend Replaced = replace("old", "new", Column)
```

## Case/Switch
```kql
| extend Category = case(Column == "A", "Alpha", Column == "B", "Beta", "Other")
```

## If/Else
```kql
| extend IsAdmin = iff(Role == "Admin", true, false)
```

## Useful Functions
- `count()`, `sum()`, `avg()`, `min()`, `max()`
- `distinct Column`
- `top 10 by Column desc`
- `project-away Column`
- `mv-expand MultiValueColumn`
- `todynamic(Column)` (parse JSON)
- `tostring(Column)`

## Security-Specific Patterns
```kql
// Find failed logins
SigninLogs | where ResultType != 0

// Find rare parent-child process relationships
DeviceProcessEvents
| summarize count() by InitiatingProcessFileName, FileName
| where count_ < 5

// Find new processes on endpoints
DeviceProcessEvents
| where Timestamp > ago(1h)
| summarize by FileName
```

---

For more, see the [KQL documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/) and [Defender Advanced Hunting docs](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview).
