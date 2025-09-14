"use client";
import { useState, useEffect } from "react";

const StrategySelector = ({ 
  initialConfig = null, 
  onConfigChange, 
  sqliDialectMLAvailable = false 
}) => {
  // Default configuration for Smart-XSS (Auto)
  const defaultConfig = {
    strategy: "smart_xss",
    families: ["xss", "sqli"],
    xss: {
      ml_mode: "auto",
      tau_ml: 0.80,
      rule_conf_gate: 0.85,
      topk: 3
    },
    sqli: {
      dialect_mode: "rules",
      short_circuit: { enabled: true, M: 12, K: 20 },
      topk: 6
    }
  };

  const [config, setConfig] = useState(initialConfig || defaultConfig);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Notify parent of initial config if not provided
  useEffect(() => {
    if (!initialConfig) {
      onConfigChange?.(defaultConfig);
    }
  }, [initialConfig, onConfigChange]);

  // Strategy presets
  const presets = {
    rules_only: {
      name: "Rules-Only",
      description: "Baseline scanning with traditional probes only",
      config: {
        strategy: "rules_only",
        families: ["xss", "sqli"],
        xss: {
          ml_mode: "never",
          tau_ml: 0.80,
          rule_conf_gate: 0.85,
          topk: 3
        },
        sqli: {
          dialect_mode: "rules",
          short_circuit: { enabled: true, M: 12, K: 20 },
          topk: 6
        }
      }
    },
    smart_xss: {
      name: "Smart-XSS (Auto)",
      description: "XSS ML with auto mode, SQLi rules-based",
      config: {
        strategy: "smart_xss",
        families: ["xss", "sqli"],
        xss: {
          ml_mode: "auto",
          tau_ml: 0.80,
          rule_conf_gate: 0.85,
          topk: 3
        },
        sqli: {
          dialect_mode: "rules",
          short_circuit: { enabled: true, M: 12, K: 20 },
          topk: 6
        }
      }
    },
    full_smart: {
      name: "Full-Smart (Auto)",
      description: "XSS + SQLi ML with auto mode",
      config: {
        strategy: "full_smart",
        families: ["xss", "sqli"],
        xss: {
          ml_mode: "auto",
          tau_ml: 0.80,
          rule_conf_gate: 0.85,
          topk: 3
        },
        sqli: {
          ml_mode: sqliDialectMLAvailable ? "auto" : "never",
          short_circuit: { enabled: true, M: 12, K: 20 },
          topk: 6
        }
      },
      disabled: !sqliDialectMLAvailable
    },
    exhaustive: {
      name: "Exhaustive",
      description: "Heavy hunting with high Top-K, no short-circuit",
      config: {
        strategy: "exhaustive",
        families: ["xss", "sqli"],
        xss: {
          ml_mode: "always",
          tau_ml: 0.80,
          rule_conf_gate: 0.85,
          topk: 9
        },
        sqli: {
          dialect_mode: "rules",
          short_circuit: { enabled: false, M: 12, K: 20 },
          topk: 12
        }
      }
    }
  };

  // Update config when preset changes
  const handlePresetChange = (presetKey) => {
    const newConfig = { ...presets[presetKey].config };
    setConfig(newConfig);
    onConfigChange?.(newConfig);
  };

  // Update config when advanced settings change
  const handleAdvancedChange = (section, field, value) => {
    const newConfig = { ...config };
    if (section === "sqli" && field === "short_circuit") {
      newConfig[section][field] = { ...newConfig[section][field], ...value };
    } else {
      newConfig[section][field] = value;
    }
    setConfig(newConfig);
    onConfigChange?.(newConfig);
  };

  // Generate plan summary string
  const generatePlanSummary = () => {
    const xssMode = config.xss.ml_mode;
    const xssTau = config.xss.tau_ml;
    const xssRule = config.xss.rule_conf_gate;
    const xssTopk = config.xss.topk;
    
    const sqliMLMode = config.sqli.ml_mode;
    const sqliTopk = config.sqli.topk;
    const sqliSC = config.sqli.short_circuit.enabled;
    const sqliM = config.sqli.short_circuit.M;
    const sqliK = config.sqli.short_circuit.K;
    
    const families = config.families.join(", ");
    
    return `Plan: XSS=${xssMode} (τ=${xssTau}, rule=${xssRule}), XSS Top-K=${xssTopk} • SQLi=${sqliMLMode}, SQLi Top-K=${sqliTopk} • Short-circuit ${sqliSC ? `M=${sqliM}/K=${sqliK}` : 'OFF'} • Families: ${families}`;
  };

  return (
    <div className="space-y-4">
      {/* Strategy Presets */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-3">
          Assessment Strategy
        </label>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {Object.entries(presets).map(([key, preset]) => (
            <div key={key} className="relative">
              <input
                type="radio"
                id={`strategy-${key}`}
                name="strategy"
                value={key}
                checked={config.strategy === key}
                onChange={() => handlePresetChange(key)}
                disabled={preset.disabled}
                className="sr-only"
              />
              <label
                htmlFor={`strategy-${key}`}
                className={`block p-4 border-2 rounded-lg cursor-pointer transition-colors ${
                  config.strategy === key
                    ? "border-blue-500 bg-blue-50"
                    : "border-gray-200 hover:border-gray-300"
                } ${preset.disabled ? "opacity-50 cursor-not-allowed" : ""}`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium text-gray-900">
                      {preset.name}
                    </div>
                    <div className="text-sm text-gray-600 mt-1">
                      {preset.description}
                    </div>
                  </div>
                  {config.strategy === key && (
                    <div className="w-4 h-4 bg-blue-500 rounded-full flex items-center justify-center">
                      <div className="w-2 h-2 bg-white rounded-full"></div>
                    </div>
                  )}
                </div>
              </label>
            </div>
          ))}
        </div>
      </div>

      {/* Plan Summary */}
      <div className="bg-gray-50 border rounded-lg p-3">
        <div className="text-sm font-medium text-gray-700 mb-1">Plan:</div>
        <div className="text-sm text-gray-600 font-mono">
          {generatePlanSummary()}
        </div>
      </div>

      {/* Advanced Settings */}
      <details className="group">
        <summary className="cursor-pointer text-sm font-medium text-gray-700 hover:text-gray-900">
          Advanced (override preset values)
        </summary>
        <div className="mt-4 space-y-6 border-t pt-4">
          {/* XSS Settings */}
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-3">XSS Configuration</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-gray-600 mb-1">ML Mode</label>
                <select
                  value={config.xss.ml_mode}
                  onChange={(e) => handleAdvancedChange("xss", "ml_mode", e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                >
                  <option value="auto">Auto</option>
                  <option value="always">Always</option>
                  <option value="never">Never</option>
                  <option value="force_ml">Force ML</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-600 mb-1">Top-K</label>
                <input
                  type="number"
                  min="1"
                  max="20"
                  value={config.xss.topk}
                  onChange={(e) => handleAdvancedChange("xss", "topk", parseInt(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-600 mb-1">
                  ML Threshold (τ_ml): {config.xss.tau_ml}
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.01"
                  value={config.xss.tau_ml}
                  onChange={(e) => handleAdvancedChange("xss", "tau_ml", parseFloat(e.target.value))}
                  className="w-full"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-600 mb-1">
                  Rule Confidence Gate: {config.xss.rule_conf_gate}
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.01"
                  value={config.xss.rule_conf_gate}
                  onChange={(e) => handleAdvancedChange("xss", "rule_conf_gate", parseFloat(e.target.value))}
                  className="w-full"
                />
              </div>
            </div>
          </div>

          {/* SQLi Settings */}
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-3">SQLi Configuration</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-gray-600 mb-1">ML Mode</label>
                <select
                  value={config.sqli.ml_mode}
                  onChange={(e) => handleAdvancedChange("sqli", "ml_mode", e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                >
                  <option value="auto">Auto</option>
                  <option value="always">Always</option>
                  <option value="never">Never</option>
                  <option value="force_ml">Force ML</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-600 mb-1">Top-K</label>
                <input
                  type="number"
                  min="1"
                  max="20"
                  value={config.sqli.topk}
                  onChange={(e) => handleAdvancedChange("sqli", "topk", parseInt(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                />
              </div>
              <div className="md:col-span-2">
                <div className="flex items-center space-x-4">
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={config.sqli.short_circuit.enabled}
                      onChange={(e) => handleAdvancedChange("sqli", "short_circuit", { enabled: e.target.checked })}
                      className="mr-2"
                    />
                    <span className="text-xs text-gray-600">Enable Short-circuit</span>
                  </label>
                  {config.sqli.short_circuit.enabled && (
                    <>
                      <div>
                        <label className="block text-xs text-gray-600">M:</label>
                        <input
                          type="number"
                          min="1"
                          max="50"
                          value={config.sqli.short_circuit.M}
                          onChange={(e) => handleAdvancedChange("sqli", "short_circuit", { M: parseInt(e.target.value) })}
                          className="w-16 px-2 py-1 border border-gray-300 rounded text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-600">K:</label>
                        <input
                          type="number"
                          min="1"
                          max="100"
                          value={config.sqli.short_circuit.K}
                          onChange={(e) => handleAdvancedChange("sqli", "short_circuit", { K: parseInt(e.target.value) })}
                          className="w-16 px-2 py-1 border border-gray-300 rounded text-sm"
                        />
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Families */}
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-3">Vulnerability Families</h4>
            <div className="space-y-2">
              {["xss", "sqli"].map((family) => (
                <label key={family} className="flex items-center">
                  <input
                    type="checkbox"
                    checked={config.families.includes(family)}
                    onChange={(e) => {
                      const newFamilies = e.target.checked
                        ? [...config.families, family]
                        : config.families.filter(f => f !== family);
                      handleAdvancedChange("", "families", newFamilies);
                    }}
                    className="mr-2"
                  />
                  <span className="text-sm text-gray-700 uppercase">{family}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
      </details>
    </div>
  );
};

export default StrategySelector;
