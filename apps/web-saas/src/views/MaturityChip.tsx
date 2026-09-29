import { Chip, Tooltip } from '@mui/material';
import { MATURITY_LABELS, maturity, type MaturityId, type MaturityLevel } from '@sedecim/profiles';

/** Border colour only: the label keeps the text colour, so it reads on any background (axe colour-contrast). */
const BORDER: Record<MaturityLevel, string | undefined> = { 'early-release': undefined, beta: 'info.main', preview: 'warning.main', experimental: 'error.main' };

/** PANEL-07: the maturity label of a profile or function, from the catalog in @sedecim/profiles; hover says why. */
export function MaturityChip(props: { id: MaturityId } | { level: MaturityLevel; why: string }) {
  const { level, why } = 'id' in props ? maturity(props.id) : props;
  return (
    <Tooltip title={why} describeChild>
      <Chip size="small" variant="outlined" label={MATURITY_LABELS[level]} data-maturity={level} className="maturity-chip" sx={{ color: 'text.primary', borderColor: BORDER[level], borderWidth: 2 }} />
    </Tooltip>
  );
}
