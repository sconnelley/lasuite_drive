export const errorCauses = async (response: Response, data?: unknown) => {
  const errorsBody = (await response.json()) as Record<
    string,
    string | string[]
  > | null;

  const causes = errorsBody
    ? Object.entries(errorsBody)
        .map(([, value]) => value)
        .flat()
    : undefined;

  return {
    status: response.status,
    cause: causes,
    data,
  };
};

export const getOrigin = () => {
  return (
    process.env.NEXT_PUBLIC_API_ORIGIN ||
    (typeof window !== "undefined" ? window.location.origin : "")
  );
};
export const baseApiUrl = (apiVersion?: string) => {
  const origin = getOrigin();
  // Use NEXT_PUBLIC_API_VERSION if set (e.g., "drive/v1.0"), otherwise fall back to apiVersion param
  const fullVersion = process.env.NEXT_PUBLIC_API_VERSION || apiVersion || "v1.0";
  // If API_VERSION contains a prefix (e.g., "drive/v1.0"), use it; otherwise use default pattern
  if (fullVersion.includes("/")) {
    // Full format: "drive/v1.0" -> "/api/drive/v1.0/"
    const [prefix, version] = fullVersion.split("/");
    // Ensure version has "v" prefix (remove if present, then add to avoid duplication)
    const versionPart = version.startsWith("v") ? version : `v${version}`;
    return `${origin}/api/${prefix}/${versionPart}/`;
  } else {
    // Legacy format: "v1.0" or "1.0" -> "/api/v1.0/"
    const versionPath = fullVersion.startsWith("v") ? fullVersion : `v${fullVersion}`;
    return `${origin}/api/${versionPath}/`;
  }
};

export const isJson = (str: string) => {
  try {
    JSON.parse(str);
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (e) {
    return false;
  }
  return true;
};
