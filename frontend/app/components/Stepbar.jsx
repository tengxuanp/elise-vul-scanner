"use client";
import { AlertTriangle, Crosshair, CheckCircle2, FileBarChart2 } from "lucide-react";
const steps = [
  { key: "crawl",  label: "Crawl",  icon: AlertTriangle },
  { key: "probe",  label: "Probe",  icon: Crosshair },
  { key: "assess", label: "Assess", icon: CheckCircle2 },
  { key: "report", label: "Report", icon: FileBarChart2 },
];
export default function Stepbar({ active="crawl" }) {
  return (
    <ol className="grid grid-cols-4 gap-2 mb-4">
      {steps.map(s=>{ const Icon=s.icon; const on=s.key===active;
        return (<li key={s.key} className={`flex items-center gap-2 rounded-xl border p-3 ${on?"bg-white shadow border-zinc-300":"bg-zinc-100 border-zinc-200"}`}><Icon className="icon"/><span className="text-sm font-medium">{s.label}</span></li>);
      })}
    </ol>
  );
}
