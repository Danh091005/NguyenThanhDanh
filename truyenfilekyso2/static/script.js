document.getElementById("uploadForm").onsubmit = async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  const res = await fetch("/sign", {
    method: "POST",
    body: formData,
  });
  const data = await res.json();
  document.getElementById("signature").value = data.signature;
  document.getElementById("publicKey").value = data.public_key;
  document.getElementById("result").style.display = "block";
};
