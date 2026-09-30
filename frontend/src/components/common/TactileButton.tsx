import React from "react";

interface TactileButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "chassis" | "recessed" | "danger" | "ghost";
  size?: "sm" | "md" | "lg";
  icon?: React.ReactNode;
  iconRight?: React.ReactNode;
  active?: boolean;
}

export const TactileButton: React.FC<TactileButtonProps> = ({
  variant = "chassis",
  size = "md",
  icon,
  iconRight,
  active = false,
  children,
  className = "",
  style = {},
  disabled = false,
  ...props
}) => {
  const sizeStyles: Record<string, React.CSSProperties> = {
    sm: {
      padding: "6px 12px",
      fontSize: "11px",
      borderRadius: "8px",
      gap: "6px",
    },
    md: {
      padding: "9px 16px",
      fontSize: "12px",
      borderRadius: "10px",
      gap: "8px",
    },
    lg: {
      padding: "13px 24px",
      fontSize: "13px",
      borderRadius: "12px",
      gap: "10px",
      letterSpacing: "0.07em",
    },
  };

  const getVariantClass = () => {
    if (active) return "tactile-btn tactile-btn-pressed";
    switch (variant) {
      case "primary":
        return "tactile-btn tactile-btn-primary";
      case "recessed":
        return "tactile-btn tactile-btn-pressed";
      case "danger":
        return "tactile-btn tactile-btn-primary"; // Safety orange/red accent
      case "ghost":
        return "tactile-btn";
      case "chassis":
      default:
        return "tactile-btn tactile-btn-chassis";
    }
  };

  return (
    <button
      className={`${getVariantClass()} ${className}`}
      style={{
        ...sizeStyles[size],
        opacity: disabled ? 0.45 : 1,
        cursor: disabled ? "not-allowed" : "pointer",
        ...style,
      }}
      disabled={disabled}
      {...props}
    >
      {icon && <span style={{ display: "inline-flex", alignItems: "center" }}>{icon}</span>}
      {children}
      {iconRight && <span style={{ display: "inline-flex", alignItems: "center" }}>{iconRight}</span>}
    </button>
  );
};
