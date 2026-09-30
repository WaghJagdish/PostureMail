import React from "react";

interface IndustrialCardProps {
  children: React.ReactNode;
  elevation?: "base" | "floating" | "recessed" | "dark";
  bolted?: boolean;
  vents?: boolean;
  tag?: string;
  headerAction?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export const IndustrialCard: React.FC<IndustrialCardProps> = ({
  children,
  elevation = "base",
  bolted = false,
  vents = false,
  tag,
  headerAction,
  className = "",
  style = {},
}) => {
  const getElevationStyle = () => {
    switch (elevation) {
      case "floating":
        return {
          background: "var(--chassis)",
          boxShadow: "var(--shadow-floating)",
          border: "1px solid rgba(255,255,255,0.7)",
          borderRadius: "16px",
        };
      case "recessed":
        return {
          background: "var(--recessed)",
          boxShadow: "var(--shadow-recessed)",
          border: "none",
          borderRadius: "14px",
        };
      case "dark":
        return {
          background: "var(--dark-panel)",
          boxShadow: "inset 1px 1px 2px rgba(255,255,255,0.1), var(--shadow-card)",
          border: "1px solid #14181d",
          borderRadius: "16px",
          color: "var(--text-light)",
        };
      case "base":
      default:
        return {
          background: "var(--chassis)",
          boxShadow: "var(--shadow-card)",
          border: "1px solid rgba(255,255,255,0.45)",
          borderRadius: "16px",
        };
    }
  };

  return (
    <div
      className={`${bolted ? "bolted-panel" : ""} ${className}`}
      style={{
        position: "relative",
        padding: "20px 24px",
        ...getElevationStyle(),
        ...style,
      }}
    >
      {(tag || vents || headerAction) && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "16px",
            paddingBottom: "10px",
            borderBottom: elevation === "dark" ? "1px solid rgba(255,255,255,0.1)" : "1px solid rgba(186,190,204,0.35)",
          }}
        >
          {tag ? (
            <span
              className="stamped-label"
              style={{
                color: elevation === "dark" ? "#a8b2d1" : "var(--text-secondary)",
                paddingLeft: bolted ? "14px" : "0",
              }}
            >
              {tag}
            </span>
          ) : <div />}

          <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
            {headerAction}
            {vents && (
              <div className="vent-grille">
                <div className="vent-slot" />
                <div className="vent-slot" />
                <div className="vent-slot" />
              </div>
            )}
          </div>
        </div>
      )}

      {children}
    </div>
  );
};
