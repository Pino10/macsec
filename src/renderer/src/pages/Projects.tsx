import { useApp } from '../store'
import { PageHead } from '../ui'
import SourcePicker from '../components/SourcePicker'

export default function Projects(): React.JSX.Element {
  const { setPreset, setPage } = useApp()
  return (
    <>
      <PageHead title="Projects" desc="Everything you can test: your www folder (shared with Laramac), your GitHub repositories and your Azure DevOps organization." />
      <div className="ms-form glass">
        <SourcePicker
          action="Review"
          onPick={(s) => {
            setPreset(s)
            setPage('review')
          }}
        />
      </div>
    </>
  )
}
