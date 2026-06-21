import { ComingSoon } from '@/components/common/ComingSoon'
import { IconShield } from '@/components/ui/Icons'

/**
 * Guardrails content hub.
 *
 * Guardrail data is not yet served by the backend (fetchGuardrails is a stub),
 * so this hub is an honest placeholder until preventive-control content exists.
 * Listed in the sidebar now so the information architecture is complete.
 */
export function GuardrailsHub() {
  return (
    <div>
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Security Content
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Guardrails
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          Preventive controls and hardening recommendations
        </div>
      </div>

      <ComingSoon
        icon={<IconShield size={32} />}
        title="Guardrails coming soon"
        body="Preventive controls, mapped services, and risk-reduction scoring will appear here once guardrail content is available."
      />
    </div>
  )
}
