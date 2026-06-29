/**
 * SectionHeader — the consistent heading for each section of the single-scroll
 * Settings page.
 *
 * Calmer than a full-page hero: a short Raycast-red accent, a title, and an
 * optional description, sized for repeated use down one column rather than the
 * oversized 36px display heading a standalone page would use.
 */
export function SectionHeader({ title, description }: { title: string; description?: string }) {
    return (
        <header className="mb-6">
            <div
                className="h-1 w-10 mb-4 rounded-full opacity-80"
                style={{
                    background: 'repeating-linear-gradient(-45deg, #FF6363, #FF6363 4px, transparent 4px, transparent 8px)',
                }}
            />
            <h2 className="font-display text-xl md:text-2xl font-semibold text-content-primary tracking-[0.2px]">
                {title}
            </h2>
            {description && (
                <p className="text-content-secondary text-sm mt-1.5 max-w-2xl leading-relaxed">
                    {description}
                </p>
            )}
        </header>
    )
}
