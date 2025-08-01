export default function CrawlResults({ endpoints = [] }) {
  if (!endpoints.length) {
    return <p className="text-gray-500 mt-4">No endpoints found yet.</p>;
  }

  return (
    <div className="mt-4">
      <h2 className="text-xl font-semibold mb-2">Discovered Endpoints:</h2>
      <table className="table-auto w-full border">
        <thead>
          <tr className="bg-gray-200">
            <th className="border px-4 py-2">URL</th>
            <th className="border px-4 py-2">Parameters</th>
          </tr>
        </thead>
        <tbody>
          {endpoints.map((ep, idx) => (
            <tr key={idx} className="hover:bg-gray-50">
              <td className="border px-4 py-2">{ep.url}</td>
              <td className="border px-4 py-2">
                {ep.params.length ? ep.params.join(', ') : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
