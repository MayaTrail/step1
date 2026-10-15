/**
 * SectionHeader: the heading for each section of the Settings page. The page
 * header above the tabs carries the eyebrow and title, so a section only needs
 * a modest title and an optional description.
 */
export function SectionHeader({ title, description }: { title: string; description?: string }) {
    return (
        <header className="mb-5">
            <h2 className="font-display text-lg font-semibold text-content-primary">
                {title}
            </h2>
            {description && (
                <p className="text-content-secondary text-sm mt-1 max-w-2xl leading-relaxed">
                    {description}
                </p>
            )}
        </header>
    )
}
