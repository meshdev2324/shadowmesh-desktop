import React from "react";
import { motion } from "framer-motion";

interface ProfessionalButtonProps {
  onClick?: () => void;
  children: React.ReactNode;
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "sm" | "md" | "lg";
  className?: string;
  disabled?: boolean;
}

const ProfessionalButton: React.FC<ProfessionalButtonProps> = ({
  onClick,
  children,
  variant = "primary",
  size = "md",
  className = "",
  disabled = false,
}) => {
  const baseStyles = "relative overflow-hidden flex items-center justify-center transition-all duration-300 rounded-2xl font-black font-mono uppercase tracking-[0.15em]";

  const variants = {
    primary: "bg-primary/5 text-primary border border-primary/40 hover:bg-primary/15 hover:border-primary hover:text-white hover:shadow-[0_0_20px_rgba(34,211,238,0.25)]",
    secondary: "bg-white/[0.03] text-white/50 border border-white/10 hover:bg-white/[0.08] hover:text-white hover:border-white/20",
    danger: "bg-red-500/5 text-red-400 border border-red-500/40 hover:bg-red-500/15 hover:border-red-500 hover:text-white hover:shadow-[0_0_20px_rgba(239,68,68,0.25)]",
    ghost: "bg-transparent text-white/30 hover:text-white hover:bg-white/5 border border-transparent",
  };

  const sizes = {
    sm: "px-4 py-2 text-[10px]",
    md: "px-6 py-3 text-[12px]",
    lg: "px-8 py-4.5 text-[14px]",
  };

  return (
    <motion.button
      whileHover={!disabled ? { y: -2 } : {}}
      whileTap={!disabled ? { scale: 0.98 } : {}}
      onClick={onClick}
      disabled={disabled}
      className={`${baseStyles} ${variants[variant]} ${sizes[size]} ${className} ${disabled ? "opacity-30 cursor-not-allowed" : "cursor-pointer"}`}
    >
      <div className="relative z-10 flex items-center gap-2.5">
        {children}
      </div>
      {!disabled && variant === "primary" && (
        <motion.div
          initial={{ x: "-100%" }}
          whileHover={{ x: "100%" }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
          className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent z-0"
        />
      )}
    </motion.button>
  );
};

export default ProfessionalButton;
