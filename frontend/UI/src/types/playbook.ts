/**
 * Types for the playbooks endpoint (/api/playbooks/).
 *
 * A Playbook is a user-authored incident-response runbook, either written from
 * scratch or forked from the PLAYBOOK.md that ships with an emulation package.
 *
 * `body` is Markdown. The editor is a rich-text surface, so an author never
 * types or reads Markdown, but storing it keeps a user playbook interchangeable
 * with a shipped one in both directions: a fork loses nothing on the way in,
 * and the export is a file that drops straight into a detection repo.
 */

/** Authoring state. A draft is work in progress; published is ready to use. */
export type UserPlaybookStatus = 'draft' | 'published'

/**
 * Who can read the playbook.
 *
 * 'organization' currently means every enterprise user, because the backend has
 * no Organization model yet. The field exists so that sharing intent is
 * recorded now and narrows correctly when organisations land.
 */
export type UserPlaybookVisibility = 'private' | 'organization'

/** A playbook without its body, as returned by the list endpoint. */
export interface UserPlaybookListItem {
  id: string
  title: string
  slug: string
  summary: string
  /** Emulation package this was forked from; empty when authored from scratch. */
  source_emulation: string
  is_fork: boolean
  /**
   * True for the two starter playbooks seeded on signup. Only a label and a
   * hint that deleting it costs nothing; otherwise an ordinary playbook.
   */
  is_example: boolean
  status: UserPlaybookStatus
  visibility: UserPlaybookVisibility
  owner_username: string
  created_at: string
  updated_at: string
}

/** A full playbook record, including the Markdown body. */
export interface UserPlaybook extends UserPlaybookListItem {
  body: string
}

/** The writable fields, for create and update calls. */
export interface UserPlaybookDraft {
  title: string
  summary?: string
  body?: string
  status?: UserPlaybookStatus
  visibility?: UserPlaybookVisibility
}

/** Request for POST /api/playbooks/generate/. */
export interface PlaybookGenerateRequest {
  /** What the playbook should cover, in the author's words. */
  brief: string
  /**
   * Links to cite. The backend does NOT fetch these - passing a URL to a
   * server and asking it to retrieve it is server-side request forgery, and
   * this backend holds an EC2 role. They reach the model as citations only.
   */
  reference_urls?: string[]
  /** Material pasted by the author, which the model does work from. */
  reference_text?: string
}

/** An unsaved AI draft. Nothing is persisted until the author saves. */
export interface PlaybookDraft {
  /** The generated document, in the same Markdown the editor round-trips. */
  body: string
  /** What a reviewer should check before trusting it. */
  notes: string[]
}
