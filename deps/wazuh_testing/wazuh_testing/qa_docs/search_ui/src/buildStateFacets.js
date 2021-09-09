function getValueFacet(aggregations, fieldName) {
  if (
    aggregations &&
    aggregations[fieldName] &&
    aggregations[fieldName].buckets &&
    aggregations[fieldName].buckets.length > 0
  ) {
    return [
      {
        field: fieldName,
        type: "value",
        data: aggregations[fieldName].buckets.map(bucket => ({
          // Boolean values and date values require using `key_as_string`
          value: bucket.key_as_string || bucket.key,
          count: bucket.doc_count
        }))
      }
    ];
  }
}

export default function buildStateFacets(aggregations) {
  const brief = getValueFacet(aggregations, "brief");
  const name = getValueFacet(aggregations, "name");
  const group_id = getValueFacet(aggregations, "group_id");
  const tiers = getValueFacet(aggregations, "tiers");
  const operating_system = getValueFacet(aggregations, "operating_system");
  const modules = getValueFacet(aggregations, "modules");

  const facets = {
    ...(brief && { brief }),
    ...(name && { name }),
    ...(group_id && {group_id}),
    ...(tiers && {tiers}),
    ...(operating_system && {operating_system}),
    ...(modules && {modules})
  };

  if (Object.keys(facets).length > 0) {
    return facets;
  }
}
