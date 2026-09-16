import { useEffect } from 'react'
import { EditorContent, useEditor, type Editor } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import Link from '@tiptap/extension-link'
import Placeholder from '@tiptap/extension-placeholder'
import Table from '@tiptap/extension-table'
import TableRow from '@tiptap/extension-table-row'
import TableCell from '@tiptap/extension-table-cell'
import TableHeader from '@tiptap/extension-table-header'
import { Markdown } from 'tiptap-markdown'

/**
 * The prose surface inside a playbook block.
 *
 * Authors never see or type Markdown: they get bold, italic, inline code,
 * lists and links, and the component emits Markdown because that is the
 * storage format the reader and the shipped PLAYBOOK.md files share.
 *
 * The toolbar offers only inline formatting. Headings, commands, tables and
 * decisions are block types in their own right (see BlockEditor), so offering
 * them here too would let an author build structure the reader cannot see - a
 * heading typed inside a step body would never become a phase tab.
 *
 * The schema is wider than the toolbar on purpose. Anything Markdown can
 * express stays in the schema even when no button produces it, because
 * ProseMirror drops nodes it does not know: a forked PLAYBOOK.md carries
 * tables, rules and quotes, and a narrower schema would silently delete
 * content the author never touched the moment they opened the block.
 */

interface RichTextEditorProps {
  /** Markdown to load into the editor. */
  value: string
  /** Called with Markdown whenever the document changes. */
  onChange: (markdown: string) => void
  /** Disable editing, e.g. while a save is in flight. */
  disabled?: boolean
  /** Hint shown while the body is empty. */
  placeholder?: string
}

function ToolButton({
  onClick,
  active,
  disabled,
  title,
  children,
}: {
  onClick: () => void
  active?: boolean
  disabled?: boolean
  title: string
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      aria-label={title}
      aria-pressed={!!active}
      className={[
        'px-2 py-1 rounded-btn text-[0.75rem] font-mono transition-colors',
        'disabled:opacity-40 disabled:cursor-not-allowed',
        active
          ? 'bg-accent-blue/20 text-accent-blue'
          : 'text-content-secondary hover:text-content-primary hover:bg-surface-elevated',
      ].join(' ')}
    >
      {children}
    </button>
  )
}

function ToolDivider() {
  return <span className="w-px h-5 bg-border-subtle mx-1" aria-hidden="true" />
}

function Toolbar({ editor, disabled }: { editor: Editor; disabled?: boolean }) {
  return (
    <div className="flex flex-wrap items-center gap-0.5 px-2 py-1 border-b border-border-subtle bg-surface-deep">
      <ToolButton
        title="Bold"
        active={editor.isActive('bold')}
        disabled={disabled}
        onClick={() => editor.chain().focus().toggleBold().run()}
      >
        <strong>B</strong>
      </ToolButton>
      <ToolButton
        title="Italic"
        active={editor.isActive('italic')}
        disabled={disabled}
        onClick={() => editor.chain().focus().toggleItalic().run()}
      >
        <em>I</em>
      </ToolButton>
      <ToolButton
        title="Inline code"
        active={editor.isActive('code')}
        disabled={disabled}
        onClick={() => editor.chain().focus().toggleCode().run()}
      >
        {'<>'}
      </ToolButton>

      <ToolDivider />

      <ToolButton
        title="Bullet list"
        active={editor.isActive('bulletList')}
        disabled={disabled}
        onClick={() => editor.chain().focus().toggleBulletList().run()}
      >
        &bull; List
      </ToolButton>
      <ToolButton
        title="Numbered list"
        active={editor.isActive('orderedList')}
        disabled={disabled}
        onClick={() => editor.chain().focus().toggleOrderedList().run()}
      >
        1. List
      </ToolButton>

      <ToolDivider />

      <ToolButton
        title="Add or edit a link"
        active={editor.isActive('link')}
        disabled={disabled}
        onClick={() => {
          const previous = editor.getAttributes('link').href as string | undefined
          const url = window.prompt('Link URL', previous ?? 'https://')
          if (url === null) return
          if (url === '') {
            editor.chain().focus().extendMarkRange('link').unsetLink().run()
            return
          }
          editor.chain().focus().extendMarkRange('link').setLink({ href: url }).run()
        }}
      >
        Link
      </ToolButton>
    </div>
  )
}

export function RichTextEditor({
  value,
  onChange,
  disabled,
  placeholder,
}: RichTextEditorProps) {
  const editor = useEditor({
    editable: !disabled,
    extensions: [
      // heading is the one exclusion: phases and steps are blocks, and a
      // heading here would produce a section the reader's parser cannot see.
      // Everything else stays in the schema so forked content survives.
      StarterKit.configure({ heading: false }),
      Link.configure({
        openOnClick: false,
        autolink: true,
        // Never let an author smuggle a javascript: URL into a document a
        // colleague will click during an incident.
        protocols: ['http', 'https', 'mailto'],
      }),
      // Not in the toolbar - a decision block is how you author one - but a
      // forked PLAYBOOK.md opens with a Classification table, so the node has
      // to exist or that table vanishes on load.
      Table.configure({ resizable: false }),
      TableRow,
      TableHeader,
      TableCell,
      Placeholder.configure({ placeholder: placeholder ?? '' }),
      Markdown.configure({
        html: false, // raw HTML in and back out is a stored-XSS path
        tightLists: true,
        transformPastedText: true,
      }),
    ],
    content: value,
    onUpdate({ editor: ed }) {
      onChange(ed.storage.markdown.getMarkdown())
    },
    editorProps: {
      attributes: {
        class:
          'prose-playbook focus:outline-none min-h-[4.5rem] px-3 py-2 text-[0.875rem] leading-relaxed',
      },
    },
  })

  useEffect(() => {
    editor?.setEditable(!disabled)
  }, [editor, disabled])

  // Reload when the caller swaps in a different document. Guarded on a real
  // difference so echoing our own onChange back as `value` does not reset the
  // cursor on every keystroke.
  useEffect(() => {
    if (!editor) return
    const current = editor.storage.markdown.getMarkdown()
    if (current !== value) {
      editor.commands.setContent(value, false)
    }
  }, [editor, value])

  if (!editor) {
    return (
      <div className="border border-border-subtle rounded-btn min-h-[4.5rem] flex items-center justify-center text-content-dim font-mono text-sm">
        Loading editor...
      </div>
    )
  }

  return (
    <div className="border border-border-subtle rounded-btn overflow-hidden bg-surface-base">
      <Toolbar editor={editor} disabled={disabled} />
      <EditorContent editor={editor} />
    </div>
  )
}
