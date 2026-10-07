// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Fixed-width text tables.
//!
//! One column-width computation, shared by `list`, `info`, `top`, and
//! `report` rather than reimplemented in each.

/// Render `headers` and `rows` as a text table with a dashed rule beneath the
/// header row.
///
/// Column width is the widest cell in that column, header included. Columns
/// are separated by a run of spaces wide enough to keep the table readable
/// without being wasteful.
pub fn write_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();

    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.len());
            }
        }
    }

    let mut out = String::new();
    push_row(&mut out, headers.iter().map(|h| h.to_string()), &widths);

    let rule_len: usize = widths.iter().sum::<usize>() + 2 * widths.len().saturating_sub(1);
    out.push_str(&"-".repeat(rule_len));
    out.push('\n');

    for row in rows {
        push_row(&mut out, row.iter().cloned(), &widths);
    }

    out
}

/// Render `fields` as a label/value report, one pair per line.
///
/// Labels are padded to the widest label so values line up in a column, the
/// way `info` presents a single program's metadata. No header, no rule — a
/// report describes one thing, not a collection of rows.
pub fn write_fields(fields: &[(&str, String)]) -> String {
    let label_width = fields
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    for (label, value) in fields {
        out.push_str(&format!("{label:<label_width$}  {value}\n"));
    }

    out
}

fn push_row(out: &mut String, cells: impl Iterator<Item = String>, widths: &[usize]) {
    let padded: Vec<String> = cells
        .enumerate()
        .map(|(i, cell)| {
            format!(
                "{cell:<width$}",
                width = widths.get(i).copied().unwrap_or(0)
            )
        })
        .collect();

    out.push_str(padded.join("  ").trim_end());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_align_to_widest_cell() {
        let out = write_table(
            &["Interface", "Mode", "Program", "ID"],
            &[vec![
                "eth0".to_string(),
                "native".to_string(),
                "xdp_cidr".to_string(),
                "142".to_string(),
            ]],
        );

        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "header, rule, one data row");
        assert!(lines[0].starts_with("Interface"));
        assert!(lines[1].chars().all(|c| c == '-'), "rule is all dashes");
        assert!(lines[2].starts_with("eth0"));
    }

    #[test]
    fn empty_rows_still_print_header() {
        let out = write_table(&["A", "B"], &[]);
        assert_eq!(out.lines().count(), 2, "header plus rule, no data rows");
    }

    #[test]
    fn fields_align_values_to_widest_label() {
        let out = write_fields(&[
            ("Mode:", "native".to_string()),
            ("Interface:", "eth0".to_string()),
        ]);
        let lines: Vec<&str> = out.lines().collect();

        assert_eq!(lines.len(), 2, "one line per field, no header or rule");
        // "Interface:" is the widest label, so both values start at the same column.
        let mode_value_at = lines[0].find("native").unwrap();
        let iface_value_at = lines[1].find("eth0").unwrap();
        assert_eq!(mode_value_at, iface_value_at);
    }
}
