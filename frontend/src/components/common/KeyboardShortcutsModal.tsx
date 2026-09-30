import React from "react";
import { X, Keyboard } from "lucide-react";

interface KeyboardShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const KeyboardShortcutsModal: React.FC<KeyboardShortcutsModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  const shortcuts = [
    { key: "j", desc: "Move session table selection down" },
    { key: "k", desc: "Move session table selection up" },
    { key: "Enter / Space", desc: "Open selected session in Forensic Detail view" },
    { key: "/", desc: "Focus search bar in Session Table" },
    { key: "v", desc: "Open Analyst Verdict modal for selected session" },
    { key: "1 – 5", desc: "Switch between views 1–5" },
    { key: "Esc", desc: "Close drawer / modal / clear active filters" },
    { key: "?", desc: "Toggle this Keyboard Shortcuts cheat-sheet" },
  ];

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 1000,
        backgroundColor: "rgba(15,23,42,0.5)", backdropFilter: "blur(4px)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: 500, background: "#fff",
          border: "1px solid #e2e6f0", borderRadius: 14,
          boxShadow: "0 24px 48px rgba(15,23,42,0.14)", padding: 28,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
            <div style={{ width: 34, height: 34, borderRadius: 8, background: "#dbeafe", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Keyboard size={17} color="#2563eb" />
            </div>
            <div>
              <div className="font-display" style={{ fontSize: 16, fontWeight: 700, color: "#0d1b2e", letterSpacing: "-0.02em" }}>Keyboard Shortcuts</div>
              <div className="text-eyebrow" style={{ fontSize: 10, color: "#1e6fc8", marginTop: 2 }}>Analyst Console</div>
            </div>
          </div>
          <button onClick={onClose} className="btn btn-ghost btn-sm" style={{ padding: "6px" }}>
            <X size={16} />
          </button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {shortcuts.map((s, idx) => (
            <div key={idx} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "8px 12px", borderRadius: 8,
              background: "#f8fafc", border: "1px solid #f1f5f9",
            }}>
              <span style={{ fontSize: 13, color: "#475569" }}>{s.desc}</span>
              <kbd className="font-mono" style={{
                background: "#fff", border: "1px solid #e2e6f0",
                borderBottom: "2px solid #c8d0e0",
                borderRadius: 5, padding: "2px 9px",
                fontSize: 11.5, fontWeight: 600, color: "#2563eb",
                boxShadow: "0 1px 2px rgba(15,23,42,0.06)",
              }}>
                {s.key}
              </kbd>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 20, display: "flex", justifyContent: "flex-end" }}>
          <button onClick={onClose} className="btn btn-primary btn-sm">
            Got it (Esc)
          </button>
        </div>
      </div>
    </div>
  );
};
