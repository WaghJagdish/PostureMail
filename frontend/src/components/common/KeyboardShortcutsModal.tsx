import React from "react";
import { X, Keyboard } from "lucide-react";
import { TactileButton } from "./TactileButton";

interface KeyboardShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const KeyboardShortcutsModal: React.FC<KeyboardShortcutsModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  const shortcuts = [
    { key: "j", desc: "Shift Switchboard table selection down" },
    { key: "k", desc: "Shift Switchboard table selection up" },
    { key: "Enter / Space", desc: "Engage stream in Forensic Dissector view" },
    { key: "/", desc: "Engage filter slot in Switchboard" },
    { key: "v", desc: "Focus Analyst Verdict stamp control" },
    { key: "1 – 6", desc: "Switch between console bays 1–6 (6: Summary Report)" },
    { key: "Esc", desc: "Disengage dialog / clear active filters" },
    { key: "?", desc: "Toggle this Operator Instruction plate" },
  ];

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1000,
        backgroundColor: "rgba(18, 24, 32, 0.65)",
        backdropFilter: "blur(6px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
      onClick={onClose}
    >
      <div
        className="bolted-panel"
        style={{
          width: 520,
          background: "var(--chassis)",
          borderRadius: 18,
          boxShadow: "16px 16px 36px rgba(0,0,0,0.4), -8px -8px 24px rgba(255,255,255,0.7)",
          padding: "26px 30px",
          border: "1px solid rgba(255,255,255,0.6)",
          position: "relative",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20, paddingLeft: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 8,
                background: "var(--recessed)",
                boxShadow: "var(--shadow-recessed)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Keyboard size={18} color="var(--accent)" />
            </div>
            <div>
              <div className="tabular-mono" style={{ fontSize: 15, fontWeight: 800, color: "var(--text-primary)" }}>
                OPERATOR INSTRUCTION MANUAL
              </div>
              <div className="stamped-label" style={{ fontSize: 9.5, color: "var(--accent)" }}>
                PECFF HARDWARE COMMAND INTERFACE
              </div>
            </div>
          </div>

          <TactileButton variant="chassis" size="sm" onClick={onClose} style={{ padding: "6px 8px" }}>
            <X size={15} />
          </TactileButton>
        </div>

        {/* Shortcuts List */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {shortcuts.map((s, idx) => (
            <div
              key={idx}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "8px 14px",
                borderRadius: 10,
                background: "var(--recessed)",
                boxShadow: "var(--shadow-recessed)",
              }}
            >
              <span style={{ fontSize: 12, color: "var(--text-primary)", fontWeight: 500 }}>{s.desc}</span>
              <kbd
                className="tabular-mono"
                style={{
                  background: "var(--chassis)",
                  boxShadow: "var(--shadow-card)",
                  border: "1px solid rgba(255,255,255,0.8)",
                  borderRadius: 6,
                  padding: "3px 10px",
                  fontSize: 11,
                  fontWeight: 700,
                  color: "var(--accent)",
                }}
              >
                {s.key}
              </kbd>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div style={{ marginTop: 22, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span className="stamped-label" style={{ fontSize: 9.5, color: "var(--text-muted)" }}>
            HOTKEY SYSTEM ACTIVE
          </span>
          <TactileButton variant="primary" size="md" onClick={onClose}>
            DISMISS [ESC]
          </TactileButton>
        </div>
      </div>
    </div>
  );
};
