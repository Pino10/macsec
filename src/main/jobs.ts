import { EventEmitter } from 'events'
import type { JobInfo } from '../shared/types'

type Updater = (percent: number | null, label?: string) => void

/** Tracks long-running tasks (downloads, installs) so the UI can show progress. */
class JobManager extends EventEmitter {
  private jobs = new Map<string, JobInfo>()
  private counter = 0

  list(): JobInfo[] {
    return [...this.jobs.values()]
  }

  private publish(): void {
    this.emit('changed', this.list())
  }

  async run<T>(label: string, task: (update: Updater) => Promise<T>): Promise<T> {
    const id = `job-${++this.counter}`
    const job: JobInfo = { id, label, percent: null, status: 'running' }
    this.jobs.set(id, job)
    this.publish()

    const update: Updater = (percent, newLabel) => {
      job.percent = percent
      if (newLabel) job.label = newLabel
      this.publish()
    }

    try {
      const result = await task(update)
      job.status = 'done'
      job.percent = 100
      this.publish()
      this.emit('finished', job)
      setTimeout(() => this.remove(id), 4000)
      return result
    } catch (err) {
      job.status = 'error'
      job.error = err instanceof Error ? err.message : String(err)
      this.publish()
      this.emit('finished', job)
      setTimeout(() => this.remove(id), 15000)
      throw err
    }
  }

  private remove(id: string): void {
    this.jobs.delete(id)
    this.publish()
  }
}

export const jobs = new JobManager()
