import React, { useEffect, useState } from "react";
import Plot from "react-plotly.js";

function App() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("http://127.0.0.1:5000/grafica")
      .then(res => res.json())
      .then(fig => setData(fig)); 
  }, []);

  return (
    <div>
      <h1>Gráfica desde Flask + React</h1>
      {data ? (
        <Plot data={data.data} layout={data.layout} />
      ) : (
        <p>Cargando gráfica...</p>
      )}
    </div>
  );
}

export default App;