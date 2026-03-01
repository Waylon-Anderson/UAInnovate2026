import { useState, useEffect } from "react";
import Papa from "papaparse";

// Vite glob (relative to project root) discovers CSVs in public/data
const csvModules = import.meta.glob("./public/data/*.csv", { query: "?url", import: "default", eager: true });

// Fallback: explicit list of files in public/data so data loads even if glob misses (e.g. wrong cwd on Windows)
const FALLBACK_FILES = [
  "auth_logs.csv",
  "auth_logs 1.csv",
  "dns_logs.csv",
  "firewall_logs.csv",
  "malware_alerts.csv",
  "malware_alerts 1.csv",
];

function getDiscovered() {
  const keys = Object.keys(csvModules);
  if (keys.length > 0) {
    return keys.map((fullPath) => {
      const filename = fullPath.replace(/^.*[/\\]/, "");
      const name = filename.replace(/\.csv$/i, "").trim();
      const url = `/data/${encodeURI(filename)}`;
      return { name, url, filename };
    });
  }
  return FALLBACK_FILES.map((filename) => {
    const name = filename.replace(/\.csv$/i, "").trim();
    const url = `/data/${encodeURI(filename)}`;
    return { name, url, filename };
  });
}

const discovered = getDiscovered();

export default function useLogData() {
  const [data,    setData]    = useState({});
  const [loading, setLoading] = useState(true);
  const [files,   setFiles]   = useState([]);
  const [stats,   setStats]   = useState({});

  useEffect(() => {
    if (discovered.length === 0) {
      setLoading(false);
      return;
    }

    Promise.all(
      discovered.map(
        ({ name, url, filename }) =>
          new Promise((resolve) =>
            Papa.parse(url, {
              download:        true,
              header:          true,
              skipEmptyLines:  "greedy",
              dynamicTyping:   false,
              transformHeader: (h) => h.trim(),
              transform:       (val) => (typeof val === "string" ? val.trim() : val),
              complete: (result) => {
                const clean = result.data.filter((row) =>
                  Object.values(row).some((v) => v !== "" && v != null)
                );
                resolve({ name, rows: clean, rawCount: result.data.length });
              },
              error: (err) => {
                console.error(`[useLogData] Failed to load "${filename}":`, err);
                resolve({ name, rows: [], rawCount: 0 });
              },
            })
          )
      )
    ).then((results) => {
      const loaded = {};
      const counts = {};
      results.forEach(({ name, rows, rawCount }) => {
        loaded[name]  = rows;
        counts[name]  = { loaded: rows.length, raw: rawCount };
      });
      setData(loaded);
      setFiles(results.map((r) => r.name));
      setStats(counts);
      setLoading(false);
    });
  }, []);

  return { data, loading, files, stats };
}
