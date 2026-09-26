// Fixture for scripts/lint-claims.ts: every marked line must be reported.
export function Landing({ n }: { n: number }) {
  return (
    <main>
      <h1>Mensajería 100% anónima</h1>
      <p title="Totalmente anónimo">Hola</p>
      <p>
        Tu actividad es <strong>100%</strong> anónima con nosotros
      </p>
      <p>Tienes {n} mensajes</p>
    </main>
  );
}
