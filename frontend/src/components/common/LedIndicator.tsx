import React from "react";

interface LedIndicatorProps {
  status: "green" | "orange" | "amber" | "red";
  label?: string;
  sublabel?: string;
  pulse?: boolean;
  size?: "sm" | "md" | "lg";
}

export const LedIndicator: React.FC<LedIndicatorProps> = ({
  status,
  label,
  sublabel,
  pulse = true,
  size = "md",
}) => {
  const sizeMap = {
    sm: { diameter: "8px", labelSize: "10px" },
    md: { diameter: "10px", labelSize: "11px" },
    lg: { diameter: "14px", labelSize: "12px" },
  };

  const currentSize = sizeMap[size];

  return (
    <div style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}>
      {/* Recessed Bezel Housing */}
      <div
        style={{
          width: `calc(${currentSize.diameter} + 6px)`,
          height: `calc(${currentSize.diameter} + 6px)`,
          borderRadius: "50%",
          background: "#d1d9e6",
          boxShadow: "inset 1px 1px 2px rgba(0,0,0,0.3), 1px 1px 1px rgba(255,255,255,0.8)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <div
          className={`led-indicator led-${status}`}
          style={{
            width: currentSize.diameter,
            height: currentSize.diameter,
            animation: pulse ? "pulse 2s infinite ease-in-out" : "none",
          }}
        />
      </div>

      {(label || sublabel) && (
        <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.1 }}>
          {label && (
            <span
              className="stamped-label"
              style={{ fontSize: currentSize.labelSize, letterSpacing: "0.06em" }}
            >
              {label}
            </span>
          )}
          {sublabel && (
            <span
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "9px",
                color: "var(--text-muted)",
                letterSpacing: "0.04em",
              }}
            >
              {sublabel}
            </span>
          )}
        </div>
      )}
    </div>
  );
};
