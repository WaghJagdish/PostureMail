import React from "react";
import { X, Keyboard } from "lucide-react";

interface KeyboardShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const KeyboardShortcutsModal: React.FC<KeyboardShortcutsModalProps> = ({
  isOpen,
  onClose,
}) => {
  if (!isOpen) return null;

  const shortcuts = [
    { key: "j", desc: "Move session table selection down" },
    { key: "k", desc: "Move session table selection up" },
    { key: "Enter / Space", desc: "Open selected session in Forensic Detail view" },
    { key: "/", desc: "Focus search bar in Session Table" },
    { key: "v", desc: "Open Analyst Verdict modal for selected session" },
    { key: "1 - 5", desc: "Switch directly between Views 1 to 5" },
    { key: "Esc", desc: "Close drawer / modal / clear active filters" },
    { key: "?", desc: "Toggle this Keyboard Shortcuts cheat-sheet" },
  ];

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(0, 0, 0, 0.7)",
        backdropFilter: "blur(4px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        className="card"
        style={{
          width: 480,
          background: "#0f172a",
          border: "1px solid #334155",
          borderRadius: 10,
          boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.6)",
          padding: 24,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, borderBottom: "1px solid var(--border-subtle)", paddingBottom: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Keyboard size={18} color="#38bdf8" />
            <h3 style={{ fontSize: 16, fontWeight: 700, color: "#f8fafc" }}>Analyst Keyboard Shortcuts</h3>
          </div>
          <button onClick={onClose} className="btn btn-secondary btn-sm" style={{ padding: "4px 6px" }}>
            <X size={15} />
          </button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {shortcuts.map((s, idx) => (
            <div
              key={idx}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "6px 10px",
                borderRadius: 6,
                background: "rgba(255, 255, 255, 0.02)",
                border: "1px solid rgba(255, 255, 255, 0.05)",
              }}
            >
              <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{s.desc}</span>
              <kbd
                className="font-mono"
                style={{
                  background: "#1e293b",
                  border: "1px solid #475569",
                  borderRadius: 4,
                  padding: "2px 8px",
                  fontSize: 11,
                  fontWeight: 600,
                  color: "#38bdf8",
                  boxShadow: "0 1px 2px rgba(0, 0, 0, 0.3)",
                }}
              >
                {s.key}
              </kbd>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 20, textAlign: "right" }}>
          <button onClick={onClose} className="btn btn-primary btn-sm">
            Got it (Esc)
          </button>
        </div>
      </div>
    </div>
  );
};
