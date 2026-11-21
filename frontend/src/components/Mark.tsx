// The apifuzz mark: a JSON object, { }, with a red terminal cursor inside it. The object is what
// the scanner probes; the cursor is the scanner at work. The braces take the text color.

export function Mark({ className }: { className?: string }) {
  return (
    <svg className={className ? `mark ${className}` : "mark"} viewBox="0 0 28 20" aria-hidden="true" focusable="false">
      <path
        className="mark__brace mark__brace--left"
        d="M9 2.5C6.6 2.5 6 3.7 6 5.5v2.2C6 9 5.2 10 3.2 10 5.2 10 6 11 6 12.3v2.2c0 1.8.6 3 3 3"
      />
      <path
        className="mark__brace mark__brace--right"
        d="M19 2.5c2.4 0 3 1.2 3 3v2.2c0 1.3.8 2.3 2.8 2.3-2 0-2.8 1-2.8 2.3v2.2c0 1.8-.6 3-3 3"
      />
      <rect className="mark__cursor" x="11.5" y="5.5" width="5" height="9" rx="0.6" />
    </svg>
  );
}
