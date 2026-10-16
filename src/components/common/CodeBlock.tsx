import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CodeBlockProps {
  code: string | object;
  language?: string;
  maxHeight?: string;
  title?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({
  code,
  maxHeight = 'max-h-72',
  title,
}) => {
  const [copied, setCopied] = useState(false);

  const formattedCode =
    typeof code === 'string'
      ? code
      : JSON.stringify(code, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(formattedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-[#070b12] overflow-hidden text-xs">
      <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900/80 border-b border-slate-800 text-slate-400">
        <span className="font-mono text-[11px] font-medium text-slate-300">
          {title || 'Payload View'}
        </span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-400 transition-colors py-0.5 px-1.5 rounded hover:bg-slate-800"
          title="Copy payload"
        >
          {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      <pre
        className={`p-3 font-mono text-slate-200 overflow-x-auto overflow-y-auto leading-relaxed select-text ${maxHeight}`}
      >
        <code>{formattedCode}</code>
      </pre>
    </div>
  );
};
