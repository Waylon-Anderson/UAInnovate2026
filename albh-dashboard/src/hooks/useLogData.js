import { useState, useEffect } from "react";
import Papa from "papaparse";

// Vite glob — picks up all CSVs including those with spaces in names
const csvModules = import.meta.glob("/public/data/*.csv", { as: "url", eager: true });

const discovered = Object.keys(csvModules).map((fullPath) => {
  const filename = fullPath.split("/").pop();             // e.g. "malware_alerts 1.csv"
  const name     = filename.replace(/\.csv$/i, "")       // "malware_alerts 1"
                           .trim();                        // trim any edge whitespace
  const url      = `/data/${filename}`;
  return { name, url, filename };
});

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

    console.log("[useLogData] Discovered files:", discovered.map((d) => d.filename));

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
                console.log(`[useLogData] "${filename}": ${clean.length} rows loaded`);
                if (result.errors.length > 0) {
                  console.warn(`[useLogData] "${filename}" warnings:`, result.errors.slice(0, 3));
                }
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

      console.log("[useLogData] All keys in data:", Object.keys(loaded));
      console.log("[useLogData] Summary:", Object.entries(counts).map(([k, v]) => `"${k}": ${v.loaded} rows`).join(", "));
    });
  }, []);

  return { data, loading, files, stats };
}