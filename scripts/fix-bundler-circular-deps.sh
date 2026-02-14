#!/bin/bash
set -e

echo "🔧 Applying bundler circular dependency fixes..."

DIST_DIR="/opt/openclaw-dev/openclaw/dist"
INLINE_EXPORT_ALL='// Inline __exportAll to avoid circular dependency
var __defProp = Object.defineProperty;
var __exportAll = (all, no_symbols) => {
\tlet target = {};
\tfor (var name in all) {
\t\t__defProp(target, name, {
\t\t\tget: all[name],
\t\t\tenumerable: true
\t\t});
\t}
\tif (!no_symbols) {
\t\t__defProp(target, Symbol.toStringTag, { value: "Module" });
\t}
\treturn target;
};'

# Function to fix a file by removing circular import and inlining __exportAll
fix_file() {
    local file="$1"
    local import_pattern="$2"

    if [ ! -f "$file" ]; then
        echo "  ⚠️  File not found: $file"
        return 1
    fi

    # Check if file has the circular import
    if grep -q "$import_pattern" "$file"; then
        echo "  📝 Fixing: $(basename "$file")"

        # Create temp file with fixes
        awk -v inline="$INLINE_EXPORT_ALL" '
            # Skip the circular import line
            $0 ~ /import.*__exportAll.*from/ { next }

            # Insert inline helper before first //#region
            !inserted && /\/\/#region/ {
                print inline
                print ""
                inserted = 1
            }

            # Print all other lines
            { print }
        ' "$file" > "$file.tmp"

        mv "$file.tmp" "$file"
        return 0
    else
        echo "  ✅ Already fixed or no circular import: $(basename "$file")"
        return 0
    fi
}

# Fix github-copilot-token chunks
echo "Fixing github-copilot-token chunks..."
for file in "$DIST_DIR"/github-copilot-token-*.js; do
    if [ -f "$file" ]; then
        fix_file "$file" "import.*__exportAll.*from"
    fi
done

# Fix plugin-sdk pi-model-discovery chunk
echo "Fixing plugin-sdk chunks..."
for file in "$DIST_DIR"/plugin-sdk/pi-model-discovery-*.js; do
    if [ -f "$file" ]; then
        fix_file "$file" "import.*__exportAll.*from.*index\.js"
    fi
done

echo "✅ Bundler circular dependency fixes applied!"
echo ""
echo "Fixed files:"
ls -1 "$DIST_DIR"/github-copilot-token-*.js 2>/dev/null | xargs -n1 basename
ls -1 "$DIST_DIR"/plugin-sdk/pi-model-discovery-*.js 2>/dev/null | xargs -n1 basename
