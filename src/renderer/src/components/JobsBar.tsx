import { useApp } from '../store'

/** Progress for downloads and installs. */
export default function JobsBar(): React.JSX.Element | null {
  const { jobs } = useApp()
  if (jobs.length === 0) return null

  return (
    <div className="stack-br no-drag" role="status" aria-live="polite">
      {jobs.map((job) => (
        <div key={job.id} className="job glass">
          <div className="job-top">
            <span>{job.label}</span>
            <span
              className="num"
              style={{ color: job.status === 'error' ? 'var(--bad)' : job.status === 'done' ? 'var(--ok)' : undefined }}
            >
              {job.status === 'error' ? 'Failed' : job.status === 'done' ? 'Done' : job.percent === null ? '' : `${job.percent}%`}
            </span>
          </div>
          {job.status === 'error' ? (
            <div style={{ color: 'var(--bad)', fontSize: 12, marginTop: 4 }}>{job.error}</div>
          ) : (
            <div className="progress">
              <div
                className={job.percent === null ? 'bar indeterminate' : 'bar'}
                style={job.percent === null ? undefined : { width: `${job.percent}%` }}
              />
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
