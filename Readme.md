# Automate Archival of incdents

## Goal
The goal of this project is to be able to reduce the amount of false positives due to behavior in the dev/staging environment. The  `/incidents` endpoint should allow us to grab all incidents listed by a specific collection. In our case the "DEV" collection. Now that we have a list of all inc's within this collection, the design to filter out and start the archival process may come in two different flavors. 
### Fine tune one query
We can fine tune the getAudits function to be dynamic enough that we can call the function in a fine tuned manner such that we receive only specific types of INC's we would like to filter out. This could be done by analyzing the other values provided to us from the endpoint to further filter down using knowledge of the INC's flooding the Prisma Cloud Console. The incidents API Documentation does not mention the ability to filter by collection, but by using the prisma cloud platform we are able to see that functionality does in fact exist.

### Multiple queries
There is also the possibility to grab all incidents per a collection, then filter for certain values on the response object that may not be available as a filter for the original query. This may seem much less performant at first, but would need a solid plan for which values we will use to further archive the Dev Collections 



#### Related documentation
https://pan.dev/compute/api/32-07/patch-audits-incidents-acknowledge-id/

https://pan.dev/compute/api/32-07/get-audits-incidents/


