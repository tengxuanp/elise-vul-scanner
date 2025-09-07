import "./globals.css";
export const metadata = { title: "Elise Scanner" };
export default function RootLayout({ children }) {
  return (<html lang="en"><body className="bg-zinc-50 text-zinc-900">{children}</body></html>);
}
